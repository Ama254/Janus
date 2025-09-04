#ifndef LLM_LOADER_H
#define LLM_LOADER_H

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <onnxruntime_c_api.h>

struct LLMConfig {
    std::string model_path;
    std::string model_name;
    int input_dim;
    int output_dim;
    bool requires_preprocessing;
    float confidence_threshold;
};

struct ModelOutput {
    std::vector<float> probabilities;
    std::vector<int64_t> predicted_class;
    float confidence;
    std::string top_class_name;
    bool is_anomaly;
};

class LLMLoader {
public:
    static LLMLoader& get_instance();
    
    bool initialize();
    bool load_model(const LLMConfig& config);
    bool unload_model(const std::string& model_name);
    bool unload_all_models();
    
    ModelOutput run_inference(const std::string& model_name, 
                            const std::vector<float>& input_features);
    
    std::vector<ModelOutput> run_sequential_inference(
        const std::vector<std::vector<float>>& sequential_data);
    
    bool is_model_loaded(const std::string& model_name) const;
    std::vector<std::string> get_loaded_models() const;
    
    ~LLMLoader();

private:
    LLMLoader();
    LLMLoader(const LLMLoader&) = delete;
    LLMLoader& operator=(const LLMLoader&) = delete;
    
    struct ModelContext {
        OrtSession* session;
        OrtAllocator* allocator;
        OrtMemoryInfo* memory_info;
        LLMConfig config;
        std::vector<const char*> input_names;
        std::vector<const char*> output_names;
    };
    
    OrtEnv* env_;
    OrtSessionOptions* session_options_;
    std::unordered_map<std::string, ModelContext> loaded_models_;
    
    bool create_session(const LLMConfig& config, ModelContext& context);
    void cleanup_session(ModelContext& context);
};

#endif