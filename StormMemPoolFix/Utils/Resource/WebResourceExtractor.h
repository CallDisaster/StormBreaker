// WebResourceExtractor.h
#pragma once
#include "pch.h"
#include <Windows.h>
#include <string>

class WebResourceExtractor {
public:
    // 提取HTML资源到文件
    static bool ExtractHtmlResource(const std::string& outputPath);

private:
    // 从模块中提取资源
    static bool ExtractResourceToFile(HMODULE hModule, int resourceId,
        LPCWSTR resourceType,
        const std::string& outputPath);
};

void TestHtmlExtraction();