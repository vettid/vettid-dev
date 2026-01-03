package main

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// HandlerCache manages compiled WASM handlers shared across all vaults
type HandlerCache struct {
	runtime  wazero.Runtime
	modules  map[string]wazero.CompiledModule
	mu       sync.RWMutex
}

// HandlerInfo describes a cached handler
type HandlerInfo struct {
	ID          string
	Name        string
	Version     string
	CompiledAt  int64
	SizeBytes   int
}

// NewHandlerCache creates a new handler cache
func NewHandlerCache() *HandlerCache {
	// Create wazero runtime with memory limits
	ctx := context.Background()
	config := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(2048) // 128 MB max per handler

	runtime := wazero.NewRuntimeWithConfig(ctx, config)

	return &HandlerCache{
		runtime: runtime,
		modules: make(map[string]wazero.CompiledModule),
	}
}

// Load compiles and caches a WASM handler
func (hc *HandlerCache) Load(ctx context.Context, id string, wasmBytes []byte) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Check if already loaded
	if _, exists := hc.modules[id]; exists {
		log.Debug().Str("handler_id", id).Msg("Handler already loaded")
		return nil
	}

	// Compile the module
	compiled, err := hc.runtime.CompileModule(ctx, wasmBytes)
	if err != nil {
		return err
	}

	hc.modules[id] = compiled

	log.Info().
		Str("handler_id", id).
		Int("modules_cached", len(hc.modules)).
		Msg("Handler loaded and cached")

	return nil
}

// Get returns a compiled module for instantiation
func (hc *HandlerCache) Get(id string) (wazero.CompiledModule, bool) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	module, exists := hc.modules[id]
	return module, exists
}

// Execute runs a handler with the given input
func (hc *HandlerCache) Execute(ctx context.Context, id string, input []byte) ([]byte, error) {
	compiled, exists := hc.Get(id)
	if !exists {
		return nil, ErrHandlerNotFound
	}

	// Create a new instance for this execution
	// Each instance is isolated but shares the compiled code
	instance, err := hc.runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().
		WithName(id).
		WithStartFunctions()) // Don't auto-run start functions
	if err != nil {
		return nil, err
	}
	defer instance.Close(ctx)

	// Call the handler's main function
	// Convention: handlers export "handle" function that takes and returns pointers
	handleFn := instance.ExportedFunction("handle")
	if handleFn == nil {
		return nil, ErrHandlerNoEntryPoint
	}

	// Allocate input in WASM memory
	inputPtr, err := allocateInWASM(ctx, instance, input)
	if err != nil {
		return nil, err
	}

	// Call handler
	results, err := handleFn.Call(ctx, uint64(inputPtr), uint64(len(input)))
	if err != nil {
		return nil, err
	}

	// Read output from WASM memory
	if len(results) < 2 {
		return nil, ErrHandlerBadReturn
	}
	outputPtr := uint32(results[0])
	outputLen := uint32(results[1])

	output, err := readFromWASM(instance, outputPtr, outputLen)
	if err != nil {
		return nil, err
	}

	return output, nil
}

// allocateInWASM allocates memory in WASM and copies data
func allocateInWASM(ctx context.Context, instance api.Module, data []byte) (uint32, error) {
	// Look for allocate function
	allocFn := instance.ExportedFunction("allocate")
	if allocFn == nil {
		return 0, ErrHandlerNoAllocate
	}

	results, err := allocFn.Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, err
	}

	ptr := uint32(results[0])

	// Copy data to WASM memory
	memory := instance.Memory()
	if memory == nil {
		return 0, ErrHandlerNoMemory
	}

	if !memory.Write(ptr, data) {
		return 0, ErrHandlerMemoryWrite
	}

	return ptr, nil
}

// readFromWASM reads data from WASM memory
func readFromWASM(instance api.Module, ptr, length uint32) ([]byte, error) {
	memory := instance.Memory()
	if memory == nil {
		return nil, ErrHandlerNoMemory
	}

	data, ok := memory.Read(ptr, length)
	if !ok {
		return nil, ErrHandlerMemoryRead
	}

	return data, nil
}

// Unload removes a handler from the cache
func (hc *HandlerCache) Unload(id string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if module, exists := hc.modules[id]; exists {
		module.Close(context.Background())
		delete(hc.modules, id)
		log.Info().Str("handler_id", id).Msg("Handler unloaded")
	}
}

// List returns information about all cached handlers
func (hc *HandlerCache) List() []HandlerInfo {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	infos := make([]HandlerInfo, 0, len(hc.modules))
	for id := range hc.modules {
		infos = append(infos, HandlerInfo{
			ID: id,
		})
	}
	return infos
}

// Close shuts down the handler cache
func (hc *HandlerCache) Close() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	ctx := context.Background()
	for id, module := range hc.modules {
		module.Close(ctx)
		delete(hc.modules, id)
	}

	return hc.runtime.Close(ctx)
}

// Handler errors
var (
	ErrHandlerNotFound     = &Error{Code: "HANDLER_NOT_FOUND", Message: "Handler not found in cache"}
	ErrHandlerNoEntryPoint = &Error{Code: "HANDLER_NO_ENTRY", Message: "Handler has no 'handle' function"}
	ErrHandlerNoAllocate   = &Error{Code: "HANDLER_NO_ALLOC", Message: "Handler has no 'allocate' function"}
	ErrHandlerNoMemory     = &Error{Code: "HANDLER_NO_MEMORY", Message: "Handler has no exported memory"}
	ErrHandlerMemoryWrite  = &Error{Code: "HANDLER_MEM_WRITE", Message: "Failed to write to handler memory"}
	ErrHandlerMemoryRead   = &Error{Code: "HANDLER_MEM_READ", Message: "Failed to read from handler memory"}
	ErrHandlerBadReturn    = &Error{Code: "HANDLER_BAD_RETURN", Message: "Handler returned unexpected values"}
)
