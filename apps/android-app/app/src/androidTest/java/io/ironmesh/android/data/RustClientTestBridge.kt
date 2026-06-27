package io.ironmesh.android.data

object RustClientTestBridge {
    init {
        System.loadLibrary("android_app")
    }

    @JvmStatic
    external fun startRendezvousRenewalScenario(): String

    @JvmStatic
    external fun getCapturedRequestPaths(): String

    @JvmStatic
    external fun getPairedSessionCount(): Int

    @JvmStatic
    external fun stopRendezvousRenewalScenario()
}
