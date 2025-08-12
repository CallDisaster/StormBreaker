# StormBreaker - 魔兽争霸3内存优化插件

## 项目简介

**StormBreaker** 是一个针对魔兽争霸3（Warcraft III 1.27a）的内存管理优化插件。通过深度Hook暴雪Storm内存池系统，尝试解决Storm内存池大块的不常用资源一直占据虚拟内存的问题。

## 🎯 核心功能

### 1. 内存池优化
- **Storm内存池Hook**：拦截并优化Storm.dll的内存分配函数
- **TLSF算法**：使用Two-Level Segregated Fit算法提供O(1)时间复杂度的内存分配
- **大块内存管理**：智能识别和管理大于128KB的内存分配
- **内存对齐**：确保16字节对齐，兼容Storm内存池格式

### 2. 内存安全保障
- **延迟释放机制**：通过统计学分析避免过早释放导致的C0000005错误
- **内存泄漏检测**：实时监控和报告潜在内存泄漏
- **损坏检测**：验证内存块完整性，防止内存踩踏
- **SEH异常保护**：全面的结构化异常处理

### 3. 寻路系统优化（可选）
- **寻路容量解锁**：突破游戏默认的单位寻路数量限制

### 4. 调试与监控
- **实时统计**：详细的内存使用统计和性能监控
- **多级日志**：支持控制台、文件、调试输出的多级日志系统
- **内存监控器**：后台监控内存状态，自动生成报告

## 🛠 技术架构

### 核心技术栈
```
┌─────────────────────────────────────────┐
│           StormBreaker 架构              │
├─────────────────────────────────────────┤
│  游戏层 (Warcraft III)                  │
│  ├── Storm.dll Hook                    │
│  └── Game.dll 寻路修复                  │
├─────────────────────────────────────────┤
│  Hook层 (StormHook)                    │
│  ├── Alloc/Free/Realloc 拦截           │
│  ├── 大块内存识别                       │
│  └── Storm兼容头部构造                  │
├─────────────────────────────────────────┤
│  内存池层 (TLSF MemoryPool)             │
│  ├── 主内存池 (64MB 初始)               │
│  ├── 扩展池管理                        │
│  └── 线程安全保证                      │
├─────────────────────────────────────────┤
│  安全层 (MemorySafety)                 │
│  ├── 延迟释放队列                      │
│  ├── 内存块跟踪                        │
│  └── 泄漏/损坏检测                     │
├─────────────────────────────────────────┤
│  基础设施                              │
│  ├── Logger (多级日志)                 │
│  ├── 性能监控                          │
│  └── 配置管理                          │
└─────────────────────────────────────────┘
```

### 关键技术要点

#### 1. **TLSF内存分配器**
- **算法优势**：O(1)分配/释放，低碎片化
- **内存池设计**：64MB初始池 + 动态扩展
- **线程安全**：读写锁保护，支持高并发

#### 2. **Hook技术实现**
```cpp
// 使用Microsoft Detours库进行函数Hook
Storm_MemAlloc_t   g_origStormAlloc   = nullptr;
Storm_MemFree_t    g_origStormFree    = nullptr;
Storm_MemReAlloc_t g_origStormReAlloc = nullptr;

// Hook函数实现Storm兼容接口
void* __fastcall Hooked_Storm_MemAlloc(int ecx, int edx, size_t size, ...);
```

#### 3. **Storm兼容性设计**
```cpp
// 10字节Storm兼容头部
#pragma pack(push, 1)
struct StormAllocHeader {
    uint16_t size;        // 用户请求大小
    uint8_t  padding;     // 对齐填充
    uint8_t  flags;       // 标志位
    void*    heapPtr;     // 堆指针
    uint16_t magic;       // 魔数0x6F6D
};
#pragma pack(pop)
```

#### 4. **延迟释放策略**
- **统计学分析**：监控内存块访问模式
- **延迟队列**：避免立即释放仍被引用的内存
- **安全阈值**：基于内存使用统计的智能释放

#### 5. **SEH异常安全**
```cpp
// 严格的SEH/C++分离设计
void* SafeTLSFMalloc(tlsf_t tlsf, size_t size) {
    __try {
        return tlsf_malloc(tlsf, size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 纯C异常处理，无C++对象
        return nullptr;
    }
}
```

## 使用方法

### 1. 安装部署
```
Game Directory/
├── game.dll
├── storm.dll
├── StormBreaker.dll          # 复制到游戏目录
└── StormBreaker/             # 日志目录（自动创建）
    ├── StormMemory.log
    └── StormMemory.log.1
```

### 2. DLL注入
使用DLL注入器或游戏启动器注入`StormBreaker.dll`：
```cpp
// 示例：程序启动时初始化
extern "C" __declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        return InitializeStormBreaker();
    case DLL_PROCESS_DETACH:
        ShutdownStormBreaker();
        break;
    }
    return TRUE;
}
```

### 3. 运行时配置
```cpp
// 内存池配置
MemoryPool::Config config;
config.initialSize = 64 * 1024 * 1024;        // 64MB初始
config.maxSize = 1024 * 1024 * 1024;          // 1GB最大
config.extendGranularity = 16 * 1024 * 1024;  // 16MB扩展粒度
MemoryPool::SetConfig(config);

// 大块拦截阈值
StormHook::SetLargeBlockThreshold(128 * 1024); // 128KB阈值
```

##  配置参数

### 日志配置
```cpp
LoggerConfig logConfig = Logger::GetDebugConfig();
logConfig.minLevel = LogLevel::Info;
logConfig.maxFileSize = 10 * 1024 * 1024;  // 10MB
logConfig.maxBackupFiles = 5;
Logger::GetInstance().Initialize(logConfig);
```

### 内存安全配置
```cpp
MemorySafetyConfig safetyConfig;
safetyConfig.enableDeferredFree = true;
safetyConfig.deferredTimeout = 30000;      // 30秒延迟
safetyConfig.maxDeferredItems = 1000;
safetyConfig.enableLeakDetection = true;
MemorySafety::GetInstance().Initialize(safetyConfig);
```

##  监控与调试

### 实时统计
```cpp
// 内存池统计
auto poolStats = MemoryPool::GetStats();
printf("总大小: %zu MB, 已用: %zu MB (%.1f%%)\n",
    poolStats.totalSize / (1024 * 1024),
    poolStats.usedSize / (1024 * 1024),
    poolStats.usedSize * 100.0 / poolStats.totalSize);

// Hook统计
printf("管理块: %zu, 总大小: %zu MB\n",
    StormHook::GetManagedBlockCount(),
    StormHook::GetTotalManagedSize() / (1024 * 1024));
```

### 日志输出示例
```
[INFO] StormBreaker Logger 已初始化
[INFO] TLSF内存池初始化完成: 地址=0x12345678, 大小=64 MB
[INFO] StormHook系统初始化完成
[INFO] 分配大块: user=0x22341145, size=2 MB
[WARNING] 检测到1个潜在内存泄漏
[INFO] 内存池统计: 总计=128 MB, 已用=45 MB (35.2%)
```

## 重要说明

### 兼容性
- **游戏版本**：仅支持魔兽争霸3 1.27a版本
- **操作系统**：Windows 7/8/10/11 (x86)
- **依赖库**：无额外运行时依赖

### 安全提示
1. **备份存档**：使用前请备份游戏存档
2. **测试环境**：建议先在测试环境验证稳定性
3. **版本匹配**：确保游戏版本为1.27a

### 测试流程
1. 单元测试：验证内存池功能
2. 集成测试：在游戏环境中测试
3. 压力测试：长时间稳定性验证
4. 兼容性测试：多种游戏场景验证

## 📄 许可证

本项目采用MIT许可证，详见[LICENSE](LICENSE)文件。

## 🔗 相关资源

- [TLSF算法文档](https://github.com/mattconte/tlsf)
- [Microsoft Detours](https://github.com/Microsoft/Detours)