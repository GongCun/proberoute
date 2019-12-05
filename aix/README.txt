# 直接通過 RPM 安裝
rpm -Uvh ./popt*.rpm ./*proberoute*<aix-version>*.rpm

# 由於 AIX 不同版本可能存在兼容性問題，直接安裝如不能使用，需要通過編譯安裝。步
  驟參考 INSTALL 文件內容，如果沒有 autoheader 等工具，可以解壓 autotools.tar 并
  安裝相關 rpm 包，之後再按照 INSTALL 內容安裝。
