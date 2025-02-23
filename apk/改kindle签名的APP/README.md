此目录下的APP都是包名改成com.amazon.kindle的APP, 安装需要破解签名认证

都有以下修改:
1. 修改包名为com.amazon.kindle
2. 设置SharedUserId为com`.amazon`
3. 添加
  - `com.amazon.kindle.action.LAUNCH_KINDLE_READER` action
  - `com.amazon.kindle.action.SHOW_SETTINGS` action
  - `com.amazon.kindle.PREWARM` action
  - `com.amazon.kcp.store.StoreActivity` activity