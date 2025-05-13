#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <string.h>
#include <thread>
#include <dirent.h>
#include <regex>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sys/select.h>  // 在最上面 include
#include <signal.h>
#include <ucontext.h>

#include "log.h"
#include "zygisk.hpp"
#include "nlohmann/json.hpp"
#include "xdl.h"

#define BUFFER_SIZE 1024

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;
using json = nlohmann::json;

void sleep_for(int milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

static void sigbus_handler(int sig, siginfo_t* si, void* arg) {
    ucontext_t* uc = (ucontext_t*)arg;
    void* fault_pc = (void*)uc->uc_mcontext.pc;
    LOGE("!!! SIGBUS at PC=%p, addr=%p", fault_pc, si->si_addr);
    _exit(1);
}

void install_sigbus_handler() {
    struct sigaction sa{};
    sa.sa_sigaction = sigbus_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, nullptr);
}



void writeString(int fd, const std::string& str) {
    size_t length = str.size() + 1;
    write(fd, &length, sizeof(length));
    write(fd, str.c_str(), length);
}

std::string readString(int fd) {
    size_t length;
    
    // 加上 select 監聽超時 3 秒
    fd_set fds;
    struct timeval timeout;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    int ret = select(fd + 1, &fds, NULL, NULL, &timeout);
    if (ret <= 0) {
        LOGE("readString timeout or error");
        return "";
    }

    read(fd, &length, sizeof(length));
    if (length == 0 || length > 4096) {
        LOGE("readString invalid length");
        return "";
    }

    std::vector<char> buffer(length);
    read(fd, buffer.data(), length);
    return {buffer.data()};
}


void injection_thread(const char* target_package_name, const std::string& installation_dir, const std::string& frida_gadget_name, const std::string& frida_config_name, int time_to_sleep) {
    LOGI("Frida-gadget injection thread start for %s, gadget name: %s, usleep: %d", target_package_name, frida_gadget_name.c_str(), time_to_sleep);
    if (time_to_sleep){
        sleep_for(time_to_sleep);
    }

    // 修改路径为安装目录下的 lib/arm64 目录
    std::string gadget_path = installation_dir + "/lib/arm64/" + frida_gadget_name;
    std::string config_path = installation_dir + "/lib/arm64/" + frida_config_name;

    std::ifstream gadget_file(gadget_path);
    if (gadget_file) {
        LOGI("Gadget is ready to load from %s", gadget_path.c_str());
    } else {
        LOGE("Cannot find gadget in %s", gadget_path.c_str());
        return;
    }
  
    auto *handle = xdl_open(gadget_path.c_str(), XDL_TRY_FORCE_LOAD);
    if (handle) {
        LOGI("Injected %s with handle %p", gadget_path.c_str(), handle);
        remap_lib(gadget_path);
        return;
    }
    auto xdl_err = dlerror();
    LOGE("Failed to inject %s (xdl_open): %s", gadget_path.c_str(), xdl_err);

    handle = dlopen(gadget_path.c_str(), RTLD_NOW);
    if (handle) {
        LOGI("Injected %s with handle %p (dlopen)", gadget_path.c_str(), handle);
        remap_lib(gadget_path);
        return;
    }

    auto dl_err = dlerror();
    LOGE("Failed to inject %s (dlopen): %s", gadget_path.c_str(), dl_err);


    // 如果有权限，可以尝试删除文件，似乎没有权限
    if (unlink(gadget_path.c_str()) == 0) {
        LOGI("Deleted gadget file: %s", gadget_path.c_str());
    } else {
        LOGE("Failed to delete gadget file: %s", gadget_path.c_str());
    }

    if (unlink(config_path.c_str()) == 0) {
        LOGI("Deleted config file: %s", config_path.c_str());
    } else {
        LOGE("Failed to delete config file: %s", config_path.c_str());
    }
}

std::string getPathFromFd(int fd) {
    char buf[PATH_MAX];
    std::string fdPath = "/proc/self/fd/" + std::to_string(fd);
    ssize_t len = readlink(fdPath.c_str(), buf, sizeof(buf) - 1);
    close(fd);
    if (len != -1) {
        buf[len] = '\0';
        return {buf};
    } else {
        // Handle error
        return "";
    }
}

void copy_file(const std::string& source_path, const std::string& dest_path) {
    FILE *source_file, *dest_file;
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    source_file = fopen(source_path.c_str(), "rb");
    if (source_file == nullptr) {
        LOGE("Error opening source file: %s", source_path.c_str());
        exit(EXIT_FAILURE);
    }

    dest_file = fopen(dest_path.c_str(), "wb");
    if (dest_file == nullptr) {
        LOGE("Error opening destination file: %s", dest_path.c_str());
        fclose(source_file);
        exit(EXIT_FAILURE);
    }

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, source_file)) > 0) {
        if (fwrite(buffer, 1, bytes_read, dest_file) != bytes_read) {
            LOGE("Error writing to destination file");
            fclose(source_file);
            fclose(dest_file);
            exit(EXIT_FAILURE);
        }
    }

    if (ferror(source_file)) {
        LOGE("Error reading from source file");
    }

    fclose(source_file);
    fclose(dest_file);
}

std::string find_installation_dir(const std::string& package_name) {
    const char* data_app_path = "/data/app/";
    DIR* dir = opendir(data_app_path);
    if (!dir) {
        LOGE("Failed to open /data/app");
        return "";
    }
    std::regex pattern(package_name);
    std::string pName = "";
    // 打开目录
    struct dirent* entry;
    // 读取目录中的每个条目
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        // 跳过 "." 和 ".."
        if (name == "." || name == "..") {
            continue;
        }
        // 打印文件或目录的完整路径
        std::string fullPath = std::string(data_app_path) + name;
        // 判断是否为目录或文件
        if (entry->d_type == DT_DIR) {
            if (std::regex_search(fullPath, pattern)) {
                LOGI("Success find install package");
                pName = fullPath;
                break;
            }else{
                std::string nextPath =  fullPath + "/";
                DIR* dir2 = opendir(nextPath.c_str());
                if (!dir2) {
                    LOGE("Failed to open next Path");
                    continue;
                }
                // 打开目录
                struct dirent* entry2;
                while ((entry2 = readdir(dir2)) != nullptr) {
                    std::string name2 = entry2->d_name;
                    // 跳过 "." 和 ".."
                    if (name2 == "." || name2 == "..") {
                        continue;
                    }
                    std::string fullPath2 =  nextPath + "/" + name2;
                    if (std::regex_search(fullPath2, pattern)) {
                        // 打印文件或目录的完整路径
                        pName = nextPath + name2;
                        LOGI("Success find install package %s",pName.c_str());
                        break;
                    }
                }
            }
            if (pName != ""){
                break;
            }
        } else if (entry->d_type == DT_REG) {

        } else {

        }
    }
    // 关闭目录
    closedir(dir);
    return pName;
}

class ZygiskFloridaGadget: public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->_api = api;
        this->_env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char* package_name = _env->GetStringUTFChars(args->nice_name, nullptr);
        std::string module_dir = getPathFromFd(_api->getModuleDir());
        json info;
        info["module_dir"] = module_dir;
        info["package_name"] = std::string(package_name);
        int fd = _api->connectCompanion();
        writeString(fd, info.dump());
        std::string resultString = readString(fd);
        json result = json::parse(resultString);
        if (result["code"] != 0){
            return;
        }
        LOGI("config success %s", package_name);
        _load = true;
        frida_gadget_name = result["frida_gadget_name"];
        frida_config_name = result["frida_config_name"];
        _delay = result["delay"];
        installation_dir = result["installation_dir"]; // 获取安装目录
        target_package_name = strdup(package_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override{
        if (_load) {
            // 将安装目录传递给注入线程
            if (_delay){
                std::thread t(injection_thread, target_package_name, installation_dir, frida_gadget_name, frida_config_name, _delay);
                t.detach();
            } else {
                injection_thread(target_package_name, installation_dir, frida_gadget_name, frida_config_name, _delay);
            }
        }
    }

private:
    Api *_api;
    JNIEnv *_env;
    int _delay;
    bool _load = false;
    char* target_package_name = nullptr;
    std::string frida_gadget_name;
    std::string frida_config_name;
    std::string installation_dir; // 新增成员变量
};

//static int urandom = -1;

static void companion_handler(int i) {
    std::string infoString = readString(i);
    json info = json::parse(infoString);
    std::string module_dir = info["module_dir"];
    std::string package_name = info["package_name"];
    std::string config_file_path = std::string("/data/data/com.xiaojia.xgj/files/config.json");
    std::string frida_gadget_name = "libhhh.so";
    std::string frida_config_name = "libhhh.config.so";

    //默认休眠一秒
    uint delay = 0;

    json result;
    std::ifstream configFile(config_file_path);
    if (!configFile) {
        result["code"] = 1;
        LOGE("The configuration file does not exist");
        writeString(i, result.dump());
        return;
    }

    json config;
    configFile >> config;
    if (!config.contains(package_name)) {
        result["code"] = 2;
        LOGD("No configuration for package: %s", package_name.c_str());
        writeString(i, result.dump());
        return;
    }

    // 查找安装目录
    std::string installation_dir = find_installation_dir(package_name);
    LOGI("find_installation_dir(%s) is %s", package_name.c_str(), installation_dir.c_str());
    if (installation_dir.empty()) {
        result["code"] = 3;
        LOGD("Failed to find installation directory for package: %s", package_name.c_str());
        writeString(i, result.dump());
        return;
    }
    result["installation_dir"] = installation_dir; // 将安装目录传递回去

    result["code"] = 0;
    json package_config = config[package_name];

    if (package_config.contains("inject")){
        bool inject = package_config["inject"];
        if (!inject) {
            result["code"] = 4;
            LOGE("inject is not true %s", package_name.c_str());
            writeString(i, result.dump());
            return;
        }
    }
    if (package_config.contains("delay")) {
        delay = package_config["delay"];
    } else {
        delay = 0;  // Default delay if not provided
    }

    // 构造 lib/arm64 目录路径
    std::string lib_arm64_dir = installation_dir + "/lib/arm64/";

    // 检查并创建目录（如果需要）
    struct stat st = {0};
    if (stat(lib_arm64_dir.c_str(), &st) == -1) {
        if (mkdir(lib_arm64_dir.c_str(), 0755) != 0) {
            result["code"] = 4;
            LOGE("Failed to create directory: %s", lib_arm64_dir.c_str());
            writeString(i, result.dump());
            return;
        }
    }

    LOGI("Copying config file");
    std::string copy_config_dst = lib_arm64_dir + frida_config_name;

    if (package_config.contains("config")) {
        LOGD("copy config from %s to %s", package_config["config"].get<std::string>().c_str(),
             copy_config_dst.c_str());
        copy_file(package_config["config"], copy_config_dst);
    } else {
        std::string copy_config_src = module_dir + "/libgadget.config.so";
        LOGD("copy config from %s to %s", copy_config_src.c_str(), copy_config_dst.c_str());
        copy_file(copy_config_src, copy_config_dst);
    }
    LOGI("Successfully copied config");

    LOGI("Copying gadget");
    std::string copy_gadget_dst = lib_arm64_dir + frida_gadget_name;

    if (package_config.contains("gadget")) {
        LOGD("copy gadget from %s to %s", package_config["gadget"].get<std::string>().c_str(),
             copy_gadget_dst.c_str());
        copy_file(package_config["gadget"], copy_gadget_dst);
    } else {
        std::string copy_gadget_src = module_dir + "/libgadget.so";
        LOGD("copy gadget from %s to %s", copy_gadget_src.c_str(), copy_gadget_dst.c_str());
        copy_file(copy_gadget_src, copy_gadget_dst);
    }
    LOGI("Successfully copied gadget");

    result["frida_gadget_name"] = frida_gadget_name;
    result["frida_config_name"] = frida_config_name;
    result["delay"] = delay;
    writeString(i, result.dump());
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(ZygiskFloridaGadget)
REGISTER_ZYGISK_COMPANION(companion_handler)
