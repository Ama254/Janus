#include "data_processor.h"
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <iostream>

DataProcessor& DataProcessor::get_instance() {
    static DataProcessor instance;
    return instance;
}

DataProcessor::DataProcessor() {
    initialize_feature_masks();
}

bool DataProcessor::initialize() {
    initialize_feature_masks();
    return true;
}

void DataProcessor::initialize_feature_masks() {
    feature_masks_["environment"] = {0, 1, 2, 3, 5, 7, 8, 9, 12, 13, 15, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37};
    feature_masks_["user_pattern"] = {4, 6, 10, 11, 14, 16, 17, 23, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49};
    feature_masks_["decision"] = {50, 51, 52, 53, 54, 55, 56, 57, 58, 59};
}

std::vector<float> DataProcessor::process_environment_data(
    const std::unordered_map<std::string, float>& raw_telemetry) {
    
    std::vector<float> features(60, 0.0f);
    
    features[0] = raw_telemetry.at("rdtsc_cycles_variance");
    features[1] = raw_telemetry.at("cpuid_hypervisor_bit");
    features[2] = raw_telemetry.at("apic_id_consistency");
    features[3] = raw_telemetry.at("cpu_cores");
    features[5] = raw_telemetry.at("kernel_alloc_latency_ns");
    features[7] = raw_telemetry.at("sector_access_latency_ms");
    features[8] = raw_telemetry.at("ioctl_read_physical_media_serial");
    features[9] = raw_telemetry.at("disk_size_gb");
    features[12] = raw_telemetry.at("tcp_timestamps_consistency");
    features[13] = raw_telemetry.at("packet_inter_arrival_jitter");
    features[15] = raw_telemetry.at("syscall_sequence_entropy");
    features[18] = raw_telemetry.at("int3_handler_present");
    features[19] = raw_telemetry.at("debug_registers_active");
    features[20] = raw_telemetry.at("peb_being_debugged");
    features[21] = raw_telemetry.at("nt_global_flag");
    features[22] = raw_telemetry.at("instruction_pointer_consistency");
    features[24] = raw_telemetry.at("system_uptime_minutes");
    features[25] = raw_telemetry.at("process_count");
    features[26] = raw_telemetry.at("time_sync_discrepancy_ms");
    features[27] = raw_telemetry.at("registry_artifact_count");
    features[28] = raw_telemetry.at("driver_artifact_count");
    features[29] = raw_telemetry.at("frida_agent_detected");
    features[30] = raw_telemetry.at("gumjs_dll_loaded");
    features[31] = raw_telemetry.at("export_hook_detected");
    features[32] = raw_telemetry.at("code_cave_detected");
    features[33] = raw_telemetry.at("unbacked_threads");
    features[34] = raw_telemetry.at("apc_activity_high");
    features[35] = raw_telemetry.at("page_protection_changes");
    features[36] = raw_telemetry.at("private_ws_anomaly");
    features[37] = raw_telemetry.at("non_canonical_addr_access");
    
    return extract_critical_features(features);
}

std::vector<float> DataProcessor::process_user_pattern_data(
    const std::unordered_map<std::string, float>& user_activity) {
    
    std::vector<float> features(60, 0.0f);
    
    features[4] = user_activity.at("user_idle_time_seconds");
    features[6] = user_activity.at("memory_commit_charge_mb");
    features[10] = user_activity.at("dns_response_time_ms");
    features[11] = user_activity.at("network_adapters_count");
    features[14] = user_activity.at("branch_misprediction_rate");
    features[16] = user_activity.at("hardware_breakpoints_count");
    features[17] = user_activity.at("thread_context_anomalies");
    features[23] = user_activity.at("handle_count");
    features[38] = user_activity.at("working_set_peak_mb");
    features[39] = user_activity.at("page_fault_rate");
    features[40] = user_activity.at("vad_allocations");
    features[41] = user_activity.at("foreground_window_changes");
    features[42] = user_activity.at("network_connection_attempts");
    features[43] = user_activity.at("process_creation_rate");
    features[44] = user_activity.at("file_io_operations");
    features[45] = user_activity.at("registry_access_pattern");
    features[46] = user_activity.at("mouse_movement_entropy");
    features[47] = user_activity.at("keystroke_timing_variance");
    features[48] = user_activity.at("application_switch_rate");
    features[49] = user_activity.at("power_state_changes");
    
    return extract_critical_features(features);
}

std::vector<float> DataProcessor::process_decision_data(
    const std::vector<float>& env_features,
    const std::vector<float>& user_features) {
    
    std::vector<float> combined_features;
    combined_features.reserve(env_features.size() + user_features.size());
    combined_features.insert(combined_features.end(), env_features.begin(), env_features.end());
    combined_features.insert(combined_features.end(), user_features.begin(), user_features.end());
    
    return extract_critical_features(combined_features);
}

std::vector<float> DataProcessor::normalize_features(const std::vector<float>& features) {
    if (features.empty()) return {};
    
    auto& scaler = scalers_["default"];
    if (scaler.mean.size() != features.size()) {
        scaler = create_default_scaler(features.size());
    }
    
    std::vector<float> normalized;
    normalized.reserve(features.size());
    
    for (size_t i = 0; i < features.size(); ++i) {
        float normalized_value = (features[i] - scaler.mean[i]) / scaler.scale[i];
        normalized_value = std::max(-3.0f, std::min(3.0f, normalized_value));
        normalized.push_back(normalized_value);
    }
    
    return normalized;
}

std::vector<float> DataProcessor::extract_critical_features(const std::vector<float>& features) {
    const auto& mask = feature_masks_["environment"];
    std::vector<float> critical_features;
    critical_features.reserve(mask.size());
    
    for (auto index : mask) {
        if (index < features.size()) {
            critical_features.push_back(features[index]);
        }
    }
    
    return normalize_features(critical_features);
}

bool DataProcessor::load_scaler_parameters(const std::string& scaler_path) {
    std::ifstream file(scaler_path);
    if (!file.is_open()) return false;
    
    ScalerParams params;
    std::string line;
    
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key;
        float value;
        
        if (std::getline(iss, key, ':')) {
            std::vector<float> values;
            while (iss >> value) {
                values.push_back(value);
            }
            
            if (key == "mean") params.mean = std::move(values);
            else if (key == "scale") params.scale = std::move(values);
            else if (key == "min") params.feature_min = std::move(values);
            else if (key == "max") params.feature_max = std::move(values);
        }
    }
    
    scalers_["default"] = std::move(params);
    return true;
}

bool DataProcessor::save_scaler_parameters(const std::string& scaler_path) {
    std::ofstream file(scaler_path);
    if (!file.is_open()) return false;
    
    const auto& params = scalers_["default"];
    
    file << "mean:";
    for (float v : params.mean) file << " " << v;
    file << "\nscale:";
    for (float v : params.scale) file << " " << v;
    file << "\nmin:";
    for (float v : params.feature_min) file << " " << v;
    file << "\nmax:";
    for (float v : params.feature_max) file << " " << v;
    
    return true;
}

DataProcessor::ScalerParams DataProcessor::create_default_scaler(size_t feature_count) {
    ScalerParams params;
    params.mean.assign(feature_count, 0.0f);
    params.scale.assign(feature_count, 1.0f);
    params.feature_min.assign(feature_count, -1.0f);
    params.feature_max.assign(feature_count, 1.0f);
    return params;
}

void DataProcessor::clear_cache() {
    scalers_.clear();
}