#pragma once

#ifdef _MSC_VER
#   define EXPORT extern "C" __declspec( dllexport )
#else
#   define EXPORT extern "C"
#endif


struct AccMgr_Output {
    char *jwt;
    char *server;
    int error;
};


EXPORT AccMgr_Output AccMgr_runAndReturnJWT();

EXPORT AccMgr_Output AccMgr_openLoginDialog();

EXPORT int AccMgr_openRegistrationDialog();

EXPORT void AccMgr_Output_free(AccMgr_Output *p);
