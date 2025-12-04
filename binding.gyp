{
  "targets": [
    {
      "target_name": "lasso",
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "sources": [
        "src/lasso.cc",
        "src/server.cc",
        "src/login.cc",
        "src/logout.cc",
        "src/identity.cc",
        "src/session.cc",
        "src/provider.cc",
        "src/utils.cc"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "LASSO_JS_VERSION=\"<!@(pkg-config --modversion lasso)\""
      ],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "10.15",
            "OTHER_CFLAGS": [
              "<!@(pkg-config --cflags lasso)"
            ],
            "OTHER_LDFLAGS": [
              "<!@(pkg-config --libs lasso)"
            ]
          }
        }],
        ["OS=='linux'", {
          "cflags": [
            "-std=c++17",
            "<!@(pkg-config --cflags lasso)"
          ],
          "cflags_cc": [
            "-std=c++17",
            "<!@(pkg-config --cflags lasso)"
          ],
          "ldflags": [
            "<!@(pkg-config --libs-only-L lasso)"
          ],
          "libraries": [
            "<!@(pkg-config --libs-only-l lasso)"
          ]
        }]
      ]
    }
  ]
}
