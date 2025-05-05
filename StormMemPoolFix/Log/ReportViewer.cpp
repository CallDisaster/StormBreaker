#include "pch.h"
#include "ReportViewer.h"
#include <Windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <Shlobj.h>
#include <fstream>
#include <string>
#include <algorithm>
#include <vector>
#include "Log/MemoryTracker.h"
#include "Base/Logger.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")

// Ĭ�ϱ���Ŀ¼
static const char* DEFAULT_REPORT_DIR = "MemoryReports";


// ����HTML����ҳ��
static std::string GenerateIndexHtml(const std::vector<MemoryReportData>& reports) {
    std::stringstream html;

    html << "<!DOCTYPE html>\n"
        << "<html lang=\"zh\">\n"
        << "<head>\n"
        << "  <meta charset=\"UTF-8\">\n"
        << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        << "  <title>�ڴ汨��鿴��</title>\n"
        << "  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\n"
        << "  <link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css\" rel=\"stylesheet\">\n"
        << "  <style>\n"
        << "    body { padding: 20px; }\n"
        << "    .card { margin-bottom: 20px; transition: all 0.3s; }\n"
        << "    .card:hover { transform: translateY(-5px); box-shadow: 0 10px 20px rgba(0,0,0,0.1); }\n"
        << "    .trend-up { color: #dc3545; }\n"
        << "    .trend-down { color: #198754; }\n"
        << "    .trend-neutral { color: #6c757d; }\n"
        << "  </style>\n"
        << "</head>\n"
        << "<body>\n"
        << "  <div class=\"container\">\n"
        << "    <h1 class=\"mb-4\">�ڴ汨��鿴��</h1>\n"
        << "    <div class=\"alert alert-info\">\n"
        << "      <i class=\"fas fa-info-circle\"></i> "
        << "      �ỰID: " << (reports.empty() ? "��" : reports[0].sessionId) << "\n"
        << "      <br>��������: " << reports.size() << "\n"
        << "    </div>\n"
        << "    <div class=\"row\">\n";

    // ���±����ժҪ��Ƭ
    if (!reports.empty()) {
        const auto& latestReport = reports.back();

        html << "      <div class=\"col-md-12 mb-4\">\n"
            << "        <div class=\"card bg-light\">\n"
            << "          <div class=\"card-header bg-primary text-white\">\n"
            << "            <h4 class=\"mb-0\">�����ڴ�״̬ժҪ</h4>\n"
            << "          </div>\n"
            << "          <div class=\"card-body\">\n"
            << "            <div class=\"row\">\n"
            << "              <div class=\"col-md-3\">\n"
            << "                <div class=\"card h-100\">\n"
            << "                  <div class=\"card-body text-center\">\n"
            << "                    <h5>�ܷ����ڴ�</h5>\n"
            << "                    <h2>" << std::fixed << std::setprecision(2) << latestReport.totalAllocatedMB << " MB</h2>\n"
            << "                  </div>\n"
            << "                </div>\n"
            << "              </div>\n"
            << "              <div class=\"col-md-3\">\n"
            << "                <div class=\"card h-100\">\n"
            << "                  <div class=\"card-body text-center\">\n"
            << "                    <h5>���ͷ��ڴ�</h5>\n"
            << "                    <h2>" << std::fixed << std::setprecision(2) << latestReport.totalFreedMB << " MB</h2>\n"
            << "                  </div>\n"
            << "                </div>\n"
            << "              </div>\n"
            << "              <div class=\"col-md-3\">\n"
            << "                <div class=\"card h-100\">\n"
            << "                  <div class=\"card-body text-center\">\n"
            << "                    <h5>�ڴ�й©</h5>\n"
            << "                    <h2 class=\"" << (latestReport.leakedMemoryMB > 0 ? "text-danger" : "text-success") << "\">"
            << std::fixed << std::setprecision(2) << latestReport.leakedMemoryMB << " MB</h2>\n"
            << "                  </div>\n"
            << "                </div>\n"
            << "              </div>\n"
            << "              <div class=\"col-md-3\">\n"
            << "                <div class=\"card h-100\">\n"
            << "                  <div class=\"card-body text-center\">\n"
            << "                    <h5>δ�ͷſ���</h5>\n"
            << "                    <h2 class=\"" << (latestReport.unreleased > 0 ? "text-warning" : "text-success") << "\">"
            << latestReport.unreleased << "</h2>\n"
            << "                  </div>\n"
            << "                </div>\n"
            << "              </div>\n"
            << "            </div>\n"
            << "          </div>\n"
            << "        </div>\n"
            << "      </div>\n";
    }

    // ���б����б�
    for (int i = reports.size() - 1; i >= 0; i--) {
        const auto& report = reports[i];

        // ������ǰһ�ݱ���Ĳ��죨����У�
        std::string allocDiffClass = "trend-neutral";
        std::string allocDiffText = "";
        std::string leakDiffClass = "trend-neutral";
        std::string leakDiffText = "";

        if (i > 0) {
            const auto& prevReport = reports[i - 1];

            double allocDiff = report.totalAllocatedMB - prevReport.totalAllocatedMB;
            if (allocDiff > 0) {
                allocDiffClass = "trend-up";
                allocDiffText = " <i class=\"fas fa-arrow-up\"></i> +" +
                    std::to_string(allocDiff) + " MB";
            }
            else if (allocDiff < 0) {
                allocDiffClass = "trend-down";
                allocDiffText = " <i class=\"fas fa-arrow-down\"></i> " +
                    std::to_string(allocDiff) + " MB";
            }

            double leakDiff = report.leakedMemoryMB - prevReport.leakedMemoryMB;
            if (leakDiff > 0) {
                leakDiffClass = "trend-up";
                leakDiffText = " <i class=\"fas fa-arrow-up\"></i> +" +
                    std::to_string(leakDiff) + " MB";
            }
            else if (leakDiff < 0) {
                leakDiffClass = "trend-down";
                leakDiffText = " <i class=\"fas fa-arrow-down\"></i> " +
                    std::to_string(leakDiff) + " MB";
            }
        }

        html << "      <div class=\"col-md-4\">\n"
            << "        <div class=\"card\">\n"
            << "          <div class=\"card-header " << (i == reports.size() - 1 ? "bg-success text-white" : "bg-light") << "\">\n"
            << "            <h5 class=\"mb-0\">" << (i == reports.size() - 1 ? "���±���" : "���� #" + std::to_string(i + 1)) << "</h5>\n"
            << "          </div>\n"
            << "          <div class=\"card-body\">\n"
            << "            <p><strong>ʱ��:</strong> " << report.timestamp << "</p>\n"
            << "            <p><strong>�ܷ���:</strong> " << std::fixed << std::setprecision(2) << report.totalAllocatedMB
            << " MB <span class=\"" << allocDiffClass << "\">" << allocDiffText << "</span></p>\n"
            << "            <p><strong>���ͷ�:</strong> " << std::fixed << std::setprecision(2) << report.totalFreedMB << " MB</p>\n"
            << "            <p><strong>й©:</strong> " << std::fixed << std::setprecision(2) << report.leakedMemoryMB
            << " MB <span class=\"" << leakDiffClass << "\">" << leakDiffText << "</span></p>\n"
            << "            <p><strong>δ�ͷſ�:</strong> " << report.unreleased << "</p>\n"
            << "            <div class=\"d-flex justify-content-between\">\n"
            << "              <a href=\"" << report.reportPath << "\" class=\"btn btn-primary\" target=\"_blank\">\n"
            << "                <i class=\"fas fa-eye\"></i> �鿴\n"
            << "              </a>\n";

        if (i < reports.size() - 1) {
            html << "              <a href=\"compare.html?old=" << i << "&new=" << i + 1
                << "\" class=\"btn btn-info\" target=\"_blank\">\n"
                << "                <i class=\"fas fa-exchange-alt\"></i> ����һ�ݱȽ�\n"
                << "              </a>\n";
        }

        html << "            </div>\n"
            << "          </div>\n"
            << "        </div>\n"
            << "      </div>\n";
    }

    html << "    </div>\n"
        << "  </div>\n"
        << "  <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js\"></script>\n"
        << "</body>\n"
        << "</html>\n";

    return html.str();
}

// ���ɱȽ�ҳ��HTML
static std::string GenerateCompareHtml(const MemoryReportData& oldReport, const MemoryReportData& newReport) {
    std::stringstream html;

    html << "<!DOCTYPE html>\n"
        << "<html lang=\"zh\">\n"
        << "<head>\n"
        << "  <meta charset=\"UTF-8\">\n"
        << "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        << "  <title>�ڴ汨��Ƚ�</title>\n"
        << "  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\n"
        << "  <link href=\"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css\" rel=\"stylesheet\">\n"
        << "  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>\n"
        << "  <style>\n"
        << "    body { padding: 20px; }\n"
        << "    .trend-up { color: #dc3545; }\n"
        << "    .trend-down { color: #198754; }\n"
        << "    .trend-neutral { color: #6c757d; }\n"
        << "    .chart-container { height: 300px; }\n"
        << "  </style>\n"
        << "</head>\n"
        << "<body>\n"
        << "  <div class=\"container\">\n"
        << "    <h1 class=\"mb-4\">�ڴ汨��Ƚ�</h1>\n"
        << "    <div class=\"alert alert-info\">\n"
        << "      <i class=\"fas fa-info-circle\"></i> "
        << "      �Ƚ�ʱ�䷶Χ: " << oldReport.timestamp << " �� " << newReport.timestamp << "\n"
        << "    </div>\n"
        << "    \n"
        << "    <div class=\"row mb-4\">\n"
        << "      <div class=\"col-md-12\">\n"
        << "        <div class=\"card\">\n"
        << "          <div class=\"card-header bg-primary text-white\">\n"
        << "            <h4 class=\"mb-0\">�ڴ�ʹ������</h4>\n"
        << "          </div>\n"
        << "          <div class=\"card-body\">\n"
        << "            <div class=\"chart-container\">\n"
        << "              <canvas id=\"trendChart\"></canvas>\n"
        << "            </div>\n"
        << "          </div>\n"
        << "        </div>\n"
        << "      </div>\n"
        << "    </div>\n"
        << "    \n"
        << "    <div class=\"row mb-4\">\n";

    // �������
    double allocDiff = newReport.totalAllocatedMB - oldReport.totalAllocatedMB;
    double allocPercent = oldReport.totalAllocatedMB > 0 ?
        (allocDiff / oldReport.totalAllocatedMB * 100) : 0;

    double freeDiff = newReport.totalFreedMB - oldReport.totalFreedMB;
    double freePercent = oldReport.totalFreedMB > 0 ?
        (freeDiff / oldReport.totalFreedMB * 100) : 0;

    double leakDiff = newReport.leakedMemoryMB - oldReport.leakedMemoryMB;
    double leakPercent = oldReport.leakedMemoryMB > 0 ?
        (leakDiff / oldReport.leakedMemoryMB * 100) : 0;

    size_t unreleasedDiff = newReport.unreleased - oldReport.unreleased;
    double unreleasedPercent = oldReport.unreleased > 0 ?
        ((double)unreleasedDiff / oldReport.unreleased * 100) : 0;

    // �ܷ����ڴ�Ա�
    html << "      <div class=\"col-md-6\">\n"
        << "        <div class=\"card\">\n"
        << "          <div class=\"card-header bg-info text-white\">\n"
        << "            <h5 class=\"mb-0\">�ܷ����ڴ�</h5>\n"
        << "          </div>\n"
        << "          <div class=\"card-body\">\n"
        << "            <div class=\"row\">\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�ɱ���</h6>\n"
        << "                <h2>" << std::fixed << std::setprecision(2) << oldReport.totalAllocatedMB << " MB</h2>\n"
        << "              </div>\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�±���</h6>\n"
        << "                <h2>" << std::fixed << std::setprecision(2) << newReport.totalAllocatedMB << " MB</h2>\n"
        << "                <p class=\"" << (allocDiff > 0 ? "trend-up" : (allocDiff < 0 ? "trend-down" : "trend-neutral")) << "\">\n"
        << "                  " << (allocDiff > 0 ? "<i class=\"fas fa-arrow-up\"></i>" :
            (allocDiff < 0 ? "<i class=\"fas fa-arrow-down\"></i>" : "<i class=\"fas fa-equals\"></i>"))
        << " " << std::fixed << std::setprecision(2) << std::abs(allocPercent) << "% "
        << "(" << (allocDiff > 0 ? "+" : "") << std::fixed << std::setprecision(2) << allocDiff << " MB)"
        << "</p>\n"
        << "              </div>\n"
        << "            </div>\n"
        << "          </div>\n"
        << "        </div>\n"
        << "      </div>\n";

    // ���ͷ��ڴ�Ա�
    html << "      <div class=\"col-md-6\">\n"
        << "        <div class=\"card\">\n"
        << "          <div class=\"card-header bg-info text-white\">\n"
        << "            <h5 class=\"mb-0\">���ͷ��ڴ�</h5>\n"
        << "          </div>\n"
        << "          <div class=\"card-body\">\n"
        << "            <div class=\"row\">\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�ɱ���</h6>\n"
        << "                <h2>" << std::fixed << std::setprecision(2) << oldReport.totalFreedMB << " MB</h2>\n"
        << "              </div>\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�±���</h6>\n"
        << "                <h2>" << std::fixed << std::setprecision(2) << newReport.totalFreedMB << " MB</h2>\n"
        << "                <p class=\"" << (freeDiff > 0 ? "trend-up" : (freeDiff < 0 ? "trend-down" : "trend-neutral")) << "\">\n"
        << "                  " << (freeDiff > 0 ? "<i class=\"fas fa-arrow-up\"></i>" :
            (freeDiff < 0 ? "<i class=\"fas fa-arrow-down\"></i>" : "<i class=\"fas fa-equals\"></i>"))
        << " " << std::fixed << std::setprecision(2) << std::abs(freePercent) << "% "
        << "(" << (freeDiff > 0 ? "+" : "") << std::fixed << std::setprecision(2) << freeDiff << " MB)"
        << "</p>\n"
        << "              </div>\n"
        << "            </div>\n"
        << "          </div>\n"
        << "        </div>\n"
        << "      </div>\n";

    html << "    </div>\n"
        << "    \n"
        << "    <div class=\"row mb-4\">\n";

    // �ڴ�й©�Ա�
    html << "      <div class=\"col-md-6\">\n"
        << "        <div class=\"card\">\n"
        << "          <div class=\"card-header bg-danger text-white\">\n"
        << "            <h5 class=\"mb-0\">�ڴ�й©</h5>\n"
        << "          </div>\n"
        << "          <div class=\"card-body\">\n"
        << "            <div class=\"row\">\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�ɱ���</h6>\n"
        << "                <h2>" << std::fixed << std::setprecision(2) << oldReport.leakedMemoryMB << " MB</h2>\n"
        << "              </div>\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�±���</h6>\n"
        << "                <h2>" << std::fixed << std::setprecision(2) << newReport.leakedMemoryMB << " MB</h2>\n"
        << "                <p class=\"" << (leakDiff > 0 ? "trend-up" : (leakDiff < 0 ? "trend-down" : "trend-neutral")) << "\">\n"
        << "                  " << (leakDiff > 0 ? "<i class=\"fas fa-arrow-up\"></i>" :
            (leakDiff < 0 ? "<i class=\"fas fa-arrow-down\"></i>" : "<i class=\"fas fa-equals\"></i>"))
        << " " << std::fixed << std::setprecision(2) << std::abs(leakPercent) << "% "
        << "(" << (leakDiff > 0 ? "+" : "") << std::fixed << std::setprecision(2) << leakDiff << " MB)"
        << "</p>\n"
        << "              </div>\n"
        << "            </div>\n"
        << "          </div>\n"
        << "        </div>\n"
        << "      </div>\n";

    // δ�ͷ��ڴ��Ա�
    html << "      <div class=\"col-md-6\">\n"
        << "        <div class=\"card\">\n"
        << "          <div class=\"card-header bg-warning text-dark\">\n"
        << "            <h5 class=\"mb-0\">δ�ͷ��ڴ��</h5>\n"
        << "          </div>\n"
        << "          <div class=\"card-body\">\n"
        << "            <div class=\"row\">\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�ɱ���</h6>\n"
        << "                <h2>" << oldReport.unreleased << "</h2>\n"
        << "              </div>\n"
        << "              <div class=\"col-md-6 text-center\">\n"
        << "                <h6>�±���</h6>\n"
        << "                <h2>" << newReport.unreleased << "</h2>\n"
        << "                <p class=\"" << (unreleasedDiff > 0 ? "trend-up" : (unreleasedDiff < 0 ? "trend-down" : "trend-neutral")) << "\">\n"
        << "                  " << (unreleasedDiff > 0 ? "<i class=\"fas fa-arrow-up\"></i>" :
            (unreleasedDiff < 0 ? "<i class=\"fas fa-arrow-down\"></i>" : "<i class=\"fas fa-equals\"></i>"))
        << " " << std::fixed << std::setprecision(2) << std::abs(unreleasedPercent) << "% "
        << "(" << (unreleasedDiff > 0 ? "+" : "") << unreleasedDiff << ")"
        << "</p>\n"
        << "              </div>\n"
        << "            </div>\n"
        << "          </div>\n"
        << "        </div>\n"
        << "      </div>\n";

    html << "    </div>\n"
        << "    \n"
        << "    <div class=\"row mb-4\">\n"
        << "      <div class=\"col-md-6\">\n"
        << "        <a href=\"" << oldReport.reportPath << "\" class=\"btn btn-primary w-100\" target=\"_blank\">\n"
        << "          <i class=\"fas fa-eye\"></i> �鿴�ɱ���\n"
        << "        </a>\n"
        << "      </div>\n"
        << "      <div class=\"col-md-6\">\n"
        << "        <a href=\"" << newReport.reportPath << "\" class=\"btn btn-success w-100\" target=\"_blank\">\n"
        << "          <i class=\"fas fa-eye\"></i> �鿴�±���\n"
        << "        </a>\n"
        << "      </div>\n"
        << "    </div>\n"
        << "    \n"
        << "    <div class=\"text-center\">\n"
        << "      <a href=\"index.html\" class=\"btn btn-secondary\">\n"
        << "        <i class=\"fas fa-arrow-left\"></i> ���ر����б�\n"
        << "      </a>\n"
        << "    </div>\n"
        << "  </div>\n"
        << "  \n"
        << "  <script>\n"
        << "    // ��������ͼ\n"
        << "    document.addEventListener('DOMContentLoaded', function() {\n"
        << "      const trendCtx = document.getElementById('trendChart').getContext('2d');\n"
        << "      \n"
        << "      new Chart(trendCtx, {\n"
        << "        type: 'line',\n"
        << "        data: {\n"
        << "          labels: ['�ɱ���', '�±���'],\n"
        << "          datasets: [\n"
        << "            {\n"
        << "              label: '�ܷ����ڴ�(MB)',\n"
        << "              data: [" << oldReport.totalAllocatedMB << ", " << newReport.totalAllocatedMB << "],\n"
        << "              backgroundColor: 'rgba(54, 162, 235, 0.5)',\n"
        << "              borderColor: 'rgba(54, 162, 235, 1)',\n"
        << "              borderWidth: 2\n"
        << "            },\n"
        << "            {\n"
        << "              label: '���ͷ��ڴ�(MB)',\n"
        << "              data: [" << oldReport.totalFreedMB << ", " << newReport.totalFreedMB << "],\n"
        << "              backgroundColor: 'rgba(75, 192, 192, 0.5)',\n"
        << "              borderColor: 'rgba(75, 192, 192, 1)',\n"
        << "              borderWidth: 2\n"
        << "            },\n"
        << "            {\n"
        << "              label: '�ڴ�й©(MB)',\n"
        << "              data: [" << oldReport.leakedMemoryMB << ", " << newReport.leakedMemoryMB << "],\n"
        << "              backgroundColor: 'rgba(255, 99, 132, 0.5)',\n"
        << "              borderColor: 'rgba(255, 99, 132, 1)',\n"
        << "              borderWidth: 2\n"
        << "            }\n"
        << "          ]\n"
        << "        },\n"
        << "        options: {\n"
        << "          responsive: true,\n"
        << "          maintainAspectRatio: false,\n"
        << "          scales: { \n"
        << "            y: { beginAtZero: true, title: { display: true, text: 'MB' } }\n"
        << "          },\n"
        << "          elements: {\n"
        << "            line: { tension: 0.3 },\n"
        << "            point: { radius: 5 }\n"
        << "          }\n"
        << "        }\n"
        << "      });\n"
        << "    });\n"
        << "  </script>\n"
        << "  \n"
        << "  <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js\"></script>\n"
        << "</body>\n"
        << "</html>\n";

    return html.str();
}

// �򿪱���鿴��
void ReportViewer::OpenReportViewer(const char* reportsDir) {
    // ʹ��Ĭ��Ŀ¼��ָ��Ŀ¼
    std::string reportsDirStr = reportsDir ? reportsDir : DEFAULT_REPORT_DIR;

    // ȷ��Ŀ¼����
    if (!g_memoryTracker.EnsureDirectoryExists(reportsDirStr)) {
        LogMessage("[ReportViewer] �޷���������Ŀ¼: %s", reportsDirStr.c_str());
        return;
    }

    // ��ȡ�����б�
    g_memoryTracker.LoadReports(reportsDirStr.c_str());
    const auto& reports = g_memoryTracker.GetReportHistory();

    // ��������ҳ��
    std::string indexHtml = GenerateIndexHtml(reports);
    std::string indexPath = reportsDirStr + "/index.html";

    std::ofstream indexFile(indexPath);
    if (!indexFile.is_open()) {
        LogMessage("[ReportViewer] �޷����������ļ�: %s", indexPath.c_str());
        return;
    }

    indexFile << indexHtml;
    indexFile.close();

    // ���ɱȽ�ҳ����
    std::string comparePath = reportsDirStr + "/compare.html";
    std::string compareHtml;

    if (reports.size() >= 2) {
        compareHtml = GenerateCompareHtml(reports[0], reports[1]);
    }
    else {
        // �򵥵�ռλҳ��
        compareHtml = "<!DOCTYPE html>\n"
            "<html><head><title>�Ƚ�</title></head>\n"
            "<body><h1>��Ҫ�������ݱ�����ܱȽ�</h1></body></html>";
    }

    std::ofstream compareFile(comparePath);
    if (!compareFile.is_open()) {
        LogMessage("[ReportViewer] �޷������Ƚ��ļ�: %s", comparePath.c_str());
    }
    else {
        compareFile << compareHtml;
        compareFile.close();
    }

    // ��Ĭ��������������ҳ��
    ShellExecuteA(NULL, "open", indexPath.c_str(), NULL, NULL, SW_SHOWNORMAL);

    LogMessage("[ReportViewer] ����������д򿪱���鿴��");
}

// �ֶ������±��沢��
void ReportViewer::GenerateAndOpenReport() {
    // �����±���
    MemoryReportData report = g_memoryTracker.GenerateAndStoreReport();

    // �򿪱���鿴��
    OpenReportViewer();

}