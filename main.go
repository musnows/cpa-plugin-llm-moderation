package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct {
    uint32_t abi_version;
    void* host_ctx;
    cliproxy_host_call_fn call;
    cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct {
    uint32_t abi_version;
    cliproxy_plugin_call_fn call;
    cliproxy_plugin_free_fn free_buffer;
    cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
static const cliproxy_host_api* host_api;
static void set_host(const cliproxy_host_api* host) { host_api = host; }
static int host_call(const char* method, const uint8_t* request, size_t len, cliproxy_buffer* response) {
    if (host_api == NULL || host_api->call == NULL) return 1;
    return host_api->call(host_api->host_ctx, method, request, len, response);
}
static void host_free(void* ptr, size_t len) {
    if (host_api != NULL && host_api->free_buffer != NULL && ptr != NULL) host_api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"sync"
	"unsafe"

	"github.com/musnows/cpa-plugin-llm-moderation/internal/hostbridge"
	"github.com/musnows/cpa-plugin-llm-moderation/internal/plugin"
)

var app *plugin.App
var initMu sync.Mutex

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, api *C.cliproxy_plugin_api) C.int {
	if host == nil || api == nil || host.abi_version != 1 {
		return 1
	}
	initMu.Lock()
	defer initMu.Unlock()
	C.set_host(host)
	transport := &hostbridge.Transport{Call: callHost}
	app = plugin.New(transport, transport)
	api.abi_version = 1
	api.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	api.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	api.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, input *C.uint8_t, length C.size_t, output *C.cliproxy_buffer) C.int {
	if output == nil {
		return 1
	}
	output.ptr = nil
	output.len = 0
	if method == nil || app == nil || length > 64<<20 {
		if method != nil && C.GoString(method) == "request.intercept_before" {
			writeEnvelope(output, plugin.FailureResponse(), nil)
			return 0
		}
		writeEnvelope(output, nil, errors.New("invalid_plugin_request"))
		return 1
	}
	var raw []byte
	if input != nil && length > 0 {
		raw = C.GoBytes(unsafe.Pointer(input), C.int(length))
	}
	result, err := app.Handle(C.GoString(method), raw)
	writeEnvelope(output, result, err)
	if err != nil {
		return 1
	}
	return 0
}

func writeEnvelope(output *C.cliproxy_buffer, result any, err error) {
	value := map[string]any{"ok": err == nil}
	if err != nil {
		value["error"] = map[string]string{"code": "plugin_error", "message": err.Error()}
	} else {
		value["result"] = result
	}
	raw, _ := json.Marshal(value)
	output.ptr = C.CBytes(raw)
	output.len = C.size_t(len(raw))
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	if app != nil {
		app.Close()
	}
}

func callHost(method string, input any, output any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return errors.New("host_request_encoding_failed")
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	cRaw := C.CBytes(raw)
	defer C.free(cRaw)
	var response C.cliproxy_buffer
	code := C.host_call(cMethod, (*C.uint8_t)(cRaw), C.size_t(len(raw)), &response)
	if response.ptr != nil {
		defer C.host_free(response.ptr, response.len)
	}
	if response.ptr == nil || response.len == 0 || response.len > 32<<20 {
		return errors.New("invalid_host_response")
	}
	result := C.GoBytes(response.ptr, C.int(response.len))
	if err := hostbridge.DecodeEnvelope(result, output); err != nil {
		return err
	}
	if code != 0 {
		return errors.New("host_callback_failed")
	}
	return nil
}
