// WebResourceExtractor.cpp
#include "pch.h"
#include "WebResourceExtractor.h"
#include "resource.h" 
#include <fstream>
#include <Log/LogSystem.h>

// 获取当前模块句柄
HMODULE GetCurrentModule() {
    HMODULE hMod = NULL;
    GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        reinterpret_cast<LPCTSTR>(&GetCurrentModule),
        &hMod);
    return hMod;
}

bool WebResourceExtractor::ExtractHtmlResource(const std::string& outputPath) {
    // 获取当前模块句柄
    HMODULE hModule = GetCurrentModule();
    if (!hModule) {
        LogMessage("[WebResourceExtractor] 无法获取模块句柄，错误码: %d", GetLastError());
        return false;
    }

    // 输出模块信息用于调试
    WCHAR modulePath[MAX_PATH] = { 0 };
    GetModuleFileNameW(hModule, modulePath, MAX_PATH);

    // 转换为ANSI用于日志输出
    char ansiPath[MAX_PATH * 2] = { 0 };
    WideCharToMultiByte(CP_ACP, 0, modulePath, -1, ansiPath, sizeof(ansiPath), NULL, NULL);

    LogMessage("[WebResourceExtractor] 当前模块: %s", ansiPath);
    LogMessage("[WebResourceExtractor] 尝试从模块 %p 中提取资源 ID: %d", hModule, IDR_HTML1);

    // 尝试提取资源
    // 注意：RT_RCDATA 是 #define RT_RCDATA MAKEINTRESOURCE(10)，是一个整数类型资源标识符
    return ExtractResourceToFile(hModule, IDR_HTML1, RT_RCDATA, outputPath);
}

bool WebResourceExtractor::ExtractResourceToFile(HMODULE hModule, int resourceId,
    LPCWSTR resourceType,
    const std::string& outputPath) {

    // 使用FindResourceW明确使用Unicode版本
    HRSRC hResource = FindResourceW(hModule, MAKEINTRESOURCEW(resourceId), resourceType);
    if (!hResource) {
        LogMessage("[WebResourceExtractor] 无法找到资源 ID: %d, 错误码: %d",
            resourceId, GetLastError());

        // 尝试枚举常见资源类型
        const LPCWSTR resourceTypes[] = {
            RT_RCDATA, RT_HTML, MAKEINTRESOURCEW(23), // RT_HTML = 23
            MAKEINTRESOURCEW(3)  // RT_ICON
        };

        LogMessage("[WebResourceExtractor] 尝试其他常见资源类型...");
        for (const auto& type : resourceTypes) {
            HRSRC altRes = FindResourceW(hModule, MAKEINTRESOURCEW(resourceId), type);
            if (altRes) {
                DWORD typeValue = IS_INTRESOURCE(type) ? (DWORD)(ULONG_PTR)type : 0;
                LogMessage("[WebResourceExtractor] 使用类型 %u 找到资源!", typeValue);
                hResource = altRes;
                break;
            }
        }

        // 如果仍未找到资源，返回失败
        if (!hResource) {
            return false;
        }
    }

    // 获取资源大小
    DWORD resourceSize = SizeofResource(hModule, hResource);
    LogMessage("[WebResourceExtractor] 找到资源，大小: %d 字节", resourceSize);

    // 加载资源
    HGLOBAL hResourceData = LoadResource(hModule, hResource);
    if (!hResourceData) {
        LogMessage("[WebResourceExtractor] 无法加载资源 ID: %d, 错误码: %d",
            resourceId, GetLastError());
        return false;
    }

    // 锁定资源内存
    LPVOID resourceData = LockResource(hResourceData);
    if (!resourceData) {
        LogMessage("[WebResourceExtractor] 无法锁定资源 ID: %d", resourceId);
        return false;
    }

    // 写入文件
    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        LogMessage("[WebResourceExtractor] 无法创建文件: %s", outputPath.c_str());
        return false;
    }

    outFile.write(static_cast<const char*>(resourceData), resourceSize);
    outFile.close();

    LogMessage("[WebResourceExtractor] 已导出资源到: %s (%d 字节)",
        outputPath.c_str(), resourceSize);
    return true;
}

// 测试函数
void TestHtmlExtraction() {
    // 输出当前目录
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    LogMessage("[TEST] 当前目录: %s", currentDir);

    // 提取HTML到当前目录
    if (WebResourceExtractor::ExtractHtmlResource("test_index.html")) {
        LogMessage("[TEST] HTML资源提取成功");

        // 尝试打开文件以确认它存在
        FILE* file = nullptr;
        fopen_s(&file, "test_index.html", "r");
        if (file) {
            // 读取前100个字符以验证内容
            char buffer[101] = { 0 };
            fread(buffer, 1, 100, file);
            fclose(file);
            LogMessage("[TEST] HTML内容预览: %.100s...", buffer);
        }
        else {
            LogMessage("[TEST] 无法打开生成的文件");
        }
    }
    else {
        LogMessage("[TEST] HTML资源提取失败");
    }
}