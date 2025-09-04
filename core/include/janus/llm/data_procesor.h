#ifndef DATA_PROCESSOR_H
#define DATA_PROCESSOR_H

#include <vector>
#include <string>
#include <unordered_map>
#include <memory>

class DataProcessor {
public:
    static DataProcessor& get_instance();
    
    bool initialize();
    
    std::vector<float> process_environment_data(
        const std::unordered_map<std::string, float>& raw_telemetry);
    
    std::vector<float> process_user_pattern_data(
        const std::unordered_map<std::string, float>& user_activity);
    
    std::vector<float> process_decision_data(
        const std::vector<float>& env_features,
        const std::vector<float>& user_features);
    
    std::vector<float> normalize_features(const std::vector<float>& features);
    std::vector<float> extract_critical_features(const std::vector<float>& features);
    
    bool load_scaler_parameters(const std::string& scaler_path);
    bool save_scaler_parameters(const std::string& scaler_path);
    
    void clear_cache();

private:
    DataProcessor();
    
    struct ScalerParams {
        std::vector<float> mean;
        std::vector<float> scale;
        std::vector<float> feature_min;
        std::vector<float> feature_max;
    };
    
    std::unordered_map<std::string, ScalerParams> scalers_;
    std::unordered_map<std::string, std::vector<size_t>> feature_masks_;
    
    void initialize_feature_masks();
    ScalerParams create_default_scaler(size_t feature_count);
};

#endif