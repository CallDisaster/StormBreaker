#ifndef REPORT_VIEWER_H
#define REPORT_VIEWER_H

#include <string>           // 包含 std::string
#include <vector>           // 包含 std::vector
#include "Log/MemoryTracker.h" // 包含 MemoryReportData 定义 (请确保路径正确)

class ReportViewer {
public:
    /**
     * @brief 打开内存报告查看器的索引页面 (index.html)。
     *
     * 该方法会生成或更新报告目录下的 index.html 文件，
     * 然后尝试使用系统默认浏览器打开它。
     *
     * @param reportsDir 包含HTML报告文件的目录。如果为 nullptr，则使用默认目录 "MemoryReports"。
     */
    static void OpenReportViewer(const char* reportsDir = nullptr);

    /**
     * @brief 手动触发一次新的内存报告生成，并打开报告查看器。
     *
     * 这会调用 MemoryTracker 生成当前的内存快照报告，
     * 然后更新 index.html 并打开它。
     */
    static void GenerateAndOpenReport();

    /**
     * @brief 生成包含所有报告链接的索引页面的HTML内容。
     *
     * @param reports 包含所有已生成报告信息的向量 (MemoryReportData)。
     * @return 返回包含完整HTML内容的字符串。
     */
    static std::string GenerateIndexHtml(const std::vector<MemoryReportData>& reports);

    // 在ReportViewer.h中添加函数声明
    static void UpdateReportsOnly(const char* reportsDir = nullptr);

private:
    // 私有构造函数和析构函数，表明这是一个静态工具类，不能被实例化。
    ReportViewer() = delete;
    ~ReportViewer() = delete;

    // 禁用拷贝构造和赋值操作。
    ReportViewer(const ReportViewer&) = delete;
    ReportViewer& operator=(const ReportViewer&) = delete;

    // 内部用于生成比较页面的函数，保持私有。
    static std::string GenerateCompareHtml(const MemoryReportData& oldReport, const MemoryReportData& newReport);

};


#endif // REPORT_VIEWER_H