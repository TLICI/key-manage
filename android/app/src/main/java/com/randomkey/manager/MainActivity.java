package com.randomkey.manager;

import android.os.Bundle;
import android.view.WindowManager;
import android.webkit.WebView;

import androidx.activity.OnBackPressedCallback;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    // 禁止截屏 / 录屏 / 最近任务缩略图：否则展开的明文密码会出现在系统截图和任务预览里
    getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);

    // 实体返回键先问页面「有没有弹窗要关」。
    // 默认行为是直接结束 Activity，导入框里粘贴到一半的内容会连同进程一起消失。
    getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
      @Override
      public void handleOnBackPressed() {
        WebView web = getBridge() != null ? getBridge().getWebView() : null;
        if (web == null) {
          exitApp();
          return;
        }
        web.evaluateJavascript(
          "(function(){try{return !!(window.__handleBack && window.__handleBack())}catch(e){return false}})()",
          handled -> {
            // ValueCallback 本身就在主线程回调，不必再切线程
            if (!"true".equals(handled)) exitApp();
          }
        );
      }

      private void exitApp() {
        // 直接结束即可：单 Activity 应用里这就是返回键的默认结果，
        // 不走 dispatcher 递归，避免回调重入
        setEnabled(false);
        finish();
      }
    });
  }
}
