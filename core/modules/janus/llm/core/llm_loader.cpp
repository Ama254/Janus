#include "llm_loader.h"
#include <stdexcept>
#include <iostream>
#include <algorithm>
#include <chrono>

#define ORT_CHECK(expr) \
    if ((expr) != 0) { \
        throw std::runtime_error("ONNX Runtime error: " + std::to_string(expr)); \
    }

LLMLoader& LLMLoader::get_instance() {
    static LLMLoader instance;
    return instance;
}

LLMLoader::LLMLoader() : env_(nullptr), session_options_(nullptr) {}

LLMLoader::~LLMLoader() {
    unload_all_models();
    if (session_options_) {
        OrtReleaseSessionOptions(session_options_);
    }
    if (env_) {
        OrtReleaseEnv(env_);
    }
}

bool LLMLoader::initialize() {
    try {
        ORT_CHECK(OrtCreateEnv(ORT_LOGGING_LEVEL_WARNING, "LLMLoader", &env_));
        ORT_CHECK(OrtCreateSessionOptions(&session_options_));
        
        OrtSetSessionThreadPoolSize(session_options_, 1);
        OrtSetSessionExecutionMode(session_options_, ORT_SEQUENTIAL);
        OrtSetSessionGraphOptimizationLevel(session_options_, ORT_ENABLE_ALL);
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        return false;
    }
}

bool LLMLoader::load_model(const LLMConfig& config) {
    if (loaded_models_.find(config.model_name) != loaded_models_.end()) {
        std::cerr << "Model " << config.model_name << " is already loaded." << std::endl;
        return false;
    }
    
    ModelContext context;
    context.config = config;
    
    try {
        if (!create_session(config, context)) {
            return false;
        }
        
        loaded_models_.emplace(config.model_name, std::move(context));
        std::cout << "Model " << config.model_name << " loaded successfully." << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to load model " << config.model_name << ": " << e.what() << std::endl;
        cleanup_session(context);
        return false;
    }
}

bool LLMLoader::create_session(const LLMConfig& config, ModelContext& context) {
    ORT_CHECK(OrtCreateCpuMemoryInfo(OrtDeviceAllocator, OrtMemTypeDefault, &context.memory_info));
    ORT_CHECK(OrtCreateAllocator(env_, context.memory_info, &context.allocator));
    
    ORT_CHECK(OrtCreateSession(env_, config.model_path.c_str(), session_options_, &context.session));
    
    size_t num_input_nodes;
    OrtStatus* status = OrtSessionGetInputCount(context.session, &num_input_nodes);
    if (status != nullptr) {
        OrtReleaseStatus(status);
        return false;
    }
    
    context.input_names.resize(num_input_nodes);
    for (size_t i = 0; i < num_input_nodes; ++i) {
        char* input_name;
        ORT_CHECK(OrtSessionGetInputName(context.session, i, context.allocator, &input_name));
        context.input_names[i] = input_name;
    }
    
    size_t num_output_nodes;
    status = OrtSessionGetOutputCount(context.session, &num_output_nodes);
    if (status != nullptr) {
        OrtReleaseStatus(status);
        return false;
    }
    
    context.output_names.resize(num_output_nodes);
    for (size_t i = 0; i < num_output_nodes; ++i) {
        char* output_name;
        ORT_CHECK(OrtSessionGetOutputName(context.session, i, context.allocator, &output_name));
        context.output_names[i] = output_name;
    }
    
    return true;
}

void LLMLoader::cleanup_session(ModelContext& context) {
    if (context.session) {
        OrtReleaseSession(context.session);
        context.session = nullptr;
    }
    if (context.allocator) {
        OrtReleaseAllocator(context.allocator);
        context.allocator = nullptr;
    }
    if (context.memory_info) {
        OrtReleaseMemoryInfo(context.memory_info);
        context.memory_info = nullptr;
    }
}

bool LLMLoader::unload_model(const std::string& model_name) {
    auto it = loaded_models_.find(model_name);
    if (it == loaded_models_.end()) {
        return false;
    }
    
    cleanup_session(it->second);
    loaded_models_.erase(it);
    std::cout << "Model " << model_name << " unloaded successfully." << std::endl;
    return true;
}

bool LLMLoader::unload_all_models() {
    for (auto& [name, context] : loaded_models_) {
        cleanup_session(context);
    }
    loaded_models_.clear();
    return true;
}

ModelOutput LLMLoader::run_inference(const std::string& model_name, 
                                   const std::vector<float>& input_features) {
    ModelOutput output;
    auto it = loaded_models_.find(model_name);
    if (it == loaded_models_.end()) {
        throw std::runtime_error("Model not loaded: " + model_name);
    }
    
    auto& context = it->second;
    
    const int64_t input_shape[] = {1, static_cast<int64_t>(input_features.size())};
    
    OrtValue* input_tensor = nullptr;
    ORT_CHECK(OrtCreateTensorWithDataAsOrtValue(
        context.memory_info,
        const_cast<float*>(input_features.data()),
        input_features.size() * sizeof(float),
        input_shape,
        2,
        ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT,
        &input_tensor
    ));
    
    OrtValue* output_tensor = nullptr;
    ORT_CHECK(OrtRun(
        context.session,
        nullptr,
        context.input_names.data(),
        &input_tensor,
        1,
        context.output_names.data(),
        1,
        &output_tensor
    ));
    
    float* output_data;
    ORT_CHECK(OrtGetTensorMutableData(output_tensor, (void**)&output_data));
    
    size_t output_size;
    ORT_CHECK(OrtGetTensorShapeElementCount(output_tensor, &output_size));
    
    output.probabilities.assign(output_data, output_data + output_size);
    
    auto max_it = std::max_element(output.probabilities.begin(), output.probabilities.end());
    output.confidence = *max_it;
    output.predicted_class.push_back(std::distance(output.probabilities.begin(), max_it));
    output.is_anomaly = output.confidence < context.config.confidence_threshold;
    
    OrtReleaseValue(output_tensor);
    OrtReleaseValue(input_tensor);
    
    return output;
}

std::vector<ModelOutput> LLMLoader::run_sequential_inference(
    const std::vector<std::vector<float>>& sequential_data) {
    
    std::vector<ModelOutput> results;
    
    if (!is_model_loaded("decision_model") || 
        !is_model_loaded("environment_detector") || 
        !is_model_loaded("user_pattern_model")) {
        throw std::runtime_error("Required models not loaded");
    }
    
    for (const auto& data : sequential_data) {
        auto decision_output = run_inference("decision_model", data);
        auto env_output = run_inference("environment_detector", data);
        auto user_output = run_inference("user_pattern_model", data);
        
        results.push_back(decision_output);
        results.push_back(env_output);
        results.push_back(user_output);
    }
    
    return results;
}

bool LLMLoader::is_model_loaded(const std::string& model_name) const {
    return loaded_models_.find(model_name) != loaded_models_.end();
}

std::vector<std::string> LLMLoader::get_loaded_models() const {
    std::vector<std::string> models;
    for (const auto& [name, _] : loaded_models_) {
        models.push_back(name);
    }
    return models;
}