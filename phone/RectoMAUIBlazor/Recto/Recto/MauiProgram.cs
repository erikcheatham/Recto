using Recto.Services;
using Recto.Shared.Extensions;
using Recto.Shared.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Maui.Devices;
// Build 5 (2026-06-02): retired Recto.Services + ZXing.Net.Maui imports.
// MauiQrScannerService deleted; replaced by per-platform native services
// (IosQrScannerService / AndroidQrScannerService / NullQrScannerService).
// ZXing.Net.Maui PackageReferences dropped from Recto.csproj — see csproj
// comment block for the architectural rationale (Android 16 16KB-page
// alignment crash + iOS first-permission-grant SIGTRAP).
//
// Build 6 (2026-06-02): retired the per-platform native QR scanner
// services entirely. IosQrScannerService / AndroidQrScannerService /
// NullQrScannerService + IQrScannerService interface all deleted. The
// OS Camera + recto:// URL-scheme deep-link path is the canonical scan
// surface on both iOS and Android — operators point the OS Camera at a
// pairing QR, tap the system-generated banner, the OS routes the
// recto://pair URL to AppDelegate.OpenUrl (iOS) / MainActivity
// OnNewIntent (Android), and Home.razor's PayloadArrived event
// subscriber handles the routing. Strictly less code to maintain + no
// in-app crash surface (Android 16 ZXing crash, iOS
// first-permission-grant trap that bit Build 4 + Build 5 review). The
// pre-flight IBiometricsAvailability service (banked Build 5) stays
// alive — it's the canonical pre-Pair-button enclave-readiness probe
// that closed the OSStatus -25293 raw-dump trap.

namespace Recto;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            // Build 5 (2026-06-02): retired the ZXing.Net.Maui
            // CameraBarcodeReaderView handler registration. Native
            // platform-specific QR scanners (IosQrScannerService /
            // AndroidQrScannerService) own the camera UI directly.
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
            });

        // Reserved for v0.4 settings (BootloaderUrl override, pinned cert, etc.).
        // Today only env-var binding is wired so future settings flow without code change.
        builder.Configuration.AddEnvironmentVariables();

        // Platform / device info abstraction consumed by Recto.Shared.
        builder.Services.AddSingleton<IFormFactor, FormFactor>();

        // v0.4 phone services: Ed25519 / ECDSA P-256 keypair management +
        // pairing-state persistence. The IEnclaveKeyService impl is platform-
        // specific so the right hardware-backed path runs on each target.
#if IOS
        // Secure Enclave ONLY (P-256 + biometric ACL). The former
        // iOS-Simulator branch (DeviceType.Virtual ->
        // SoftwareEnclaveKeyService) was REMOVED 2026-08-05: software key
        // material must not be reachable from a device IPA, even behind a
        // runtime check -- the convenience it bought (App Store screenshot
        // capture, sim demo) is not worth carrying a software signing path
        // in the production binary. Simulator builds now fail Secure
        // Enclave keygen (OSStatus -25293) BY DESIGN; pairing, dev smoke
        // and screenshot capture ride real hardware.
        builder.Services.AddSingleton<IEnclaveKeyService, Recto.Platforms.iOSImpl.IosSecureEnclaveKeyService>();
        // iOS APNs push-token registration.
        builder.Services.AddSingleton<IPushTokenService, Recto.Platforms.iOSImpl.IosApnsPushTokenService>();
#elif ANDROID
        // Android StrongBox (Ed25519 + biometric, falls back to TEE if no StrongBox).
        builder.Services.AddSingleton<IEnclaveKeyService, Recto.Platforms.AndroidImpl.AndroidStrongBoxKeyService>();
        // Android FCM push-token registration.
        builder.Services.AddSingleton<IPushTokenService, Recto.Platforms.AndroidImpl.AndroidFcmPushTokenService>();
#else
        // Windows / Mac Catalyst dev-loop backing (BouncyCastle Ed25519, no enclave).
        builder.Services.AddSingleton<IEnclaveKeyService, SoftwareEnclaveKeyService>();
        // No push transport on dev hosts; pairing still works, bootloader
        // falls back to the 3s poll cycle.
        builder.Services.AddSingleton<IPushTokenService, NoOpPushTokenService>();
#endif
        builder.Services.AddSingleton<IPairingStateService, MauiPairingStateService>();
        // Genesis-membership marker + the one guarded full-wipe path. The
        // marker lives in its own storage entry (not the pairing record)
        // because it describes the enclave KEY and must survive the
        // surgical per-bootloader unpair; the wipe path guards it fail-
        // closed ahead of the first destructive call. Every UI surface
        // that destroys the identity key routes through IUnpairService.
        builder.Services.AddSingleton<IGenesisStateService, MauiGenesisStateService>();
        builder.Services.AddSingleton<IUnpairService, UnpairService>();
        // v1 vault home (banked 2026-05-18): registry of consumer services
        // the phone has been authorized to receive requests from. Derived
        // from AppContext entries observed on each pending request. Powers
        // the Authy-analog "Connected Services" list view at the top of
        // Home.razor — the canonical multi-tenant marketing surface +
        // user mental-model anchor ("services connected to my Recto").
        // SecureStorage-backed under recto.phone.connected-services so the
        // list survives app launches.
        builder.Services.AddSingleton<IConnectedServiceRegistry, MauiConnectedServiceRegistry>();
        // v0.5 universal-vault first kind: TOTP. SecureStorage-backed; secrets
        // never leave the phone. See ARCHITECTURE.md 2026-04-26 entry.
        builder.Services.AddSingleton<ITotpService, MauiTotpService>();
        // v0.5+ Ethereum signing capability. SecureStorage-backed BIP-39
        // mnemonic + BIP-32/BIP-44 derivation; one mnemonic per alias,
        // infinitely many addresses on demand at any path. Cross-platform
        // BouncyCastle math, no per-platform fan-out (Secure Enclave /
        // StrongBox don't support secp256k1, so the software impl IS the
        // correct long-term implementation).
        builder.Services.AddSingleton<IEthSignService, MauiEthSignService>();
        // v0.5+ Bitcoin signing capability. Reads the SAME BIP-39
        // mnemonic the ETH service reads (one mnemonic per phone, two
        // BIP-44 trees: m/44'/60' for ETH, m/84'/0' for BTC native
        // SegWit). BIP-137 message_signing verb is wired today; PSBT
        // (BIP-174 transaction signing) is reserved for a follow-up.
        builder.Services.AddSingleton<IBtcSignService, MauiBtcSignService>();
        // Wave-8 ed25519-chain signing capability (SOL / XLM / XRP).
        // Reads the SAME BIP-39 mnemonic the ETH and BTC services read
        // (one mnemonic per phone, three new SLIP-0010 ed25519 trees:
        // m/44'/501'/N'/0' for SOL, m/44'/148'/N' for XLM,
        // m/44'/144'/0'/0'/N' for XRP-ed25519). Single cross-platform
        // singleton — BouncyCastle ed25519 + Slip10 derivation are the
        // canonical signing primitives on all targets (no per-platform
        // fan-out; iOS Secure Enclave + Android StrongBox don't natively
        // support SLIP-0010 ed25519 derivation paths, so the software
        // BouncyCastle path IS the implementation, not a fallback).
        builder.Services.AddSingleton<IEd25519ChainSignService, MauiEd25519ChainSignService>();
        // Wave 9: TRON signing service. Same one-mnemonic-shared-across-
        // services posture as ETH/BTC/ED -- reads the same SecureStorage
        // entry (recto.phone.eth.mnemonic.{alias}). Cross-platform
        // singleton; secp256k1 + Keccak-256 reuse EthSigningOps directly.
        builder.Services.AddSingleton<ITronSignService, MauiTronSignService>();
        // v0.4.1 user preferences (polling interval, history limit, theme).
        // MAUI Preferences-backed (not SecureStorage; not secret).
        builder.Services.AddSingleton<IUserPreferencesService, MauiUserPreferencesService>();

        // Task #22 Phase 1 (banked 2026-05-31): recto://pair?... URL-
        // scheme deep-link state holder. Platform-specific URL handlers
        // (iOS AppDelegate.OpenUrl, Android MainActivity.OnCreate /
        // OnNewIntent) push validated payloads via
        // InMemoryPairDeepLinkState.SetGlobal; Home.razor consumes via
        // IPairDeepLinkState.TryConsume on OnInitializedAsync. Single-
        // consume semantics; static-backing field means platform
        // handlers can push BEFORE DI is fully bootstrapped on cold
        // launch.
        builder.Services.AddSingleton<IPairDeepLinkState, InMemoryPairDeepLinkState>();

        // Build 12 (2026-07-11, wave-C consumer): silent-push wake bridge.
        // Native receive handlers (Android RectoFirebaseMessagingService,
        // iOS AppDelegate.DidReceiveRemoteNotification) raise
        // InMemoryPushWakeSignal.SignalWakeGlobal; Home.razor subscribes to
        // IPushWakeSignal.WakeRequested and fetches pending immediately.
        // Static-backing field means a push during cold launch is safe.
        // Polling stays the fallback until APNs/FCM creds are provisioned.
        builder.Services.AddSingleton<IPushWakeSignal, InMemoryPushWakeSignal>();

        // Build 6 (2026-06-02): pre-flight biometric availability check
        // (Build 5 keepsake) stays alive. The IQrScannerService block
        // got retired with the in-app scanner (see file-top comment for
        // the architectural rationale).
        //
        // iOS biometric availability via LAContext.CanEvaluatePolicy.
        // Android biometric availability via AndroidX BiometricManager.
        //   canAuthenticate(BIOMETRIC_STRONG).
        // Windows / Mac Catalyst: null impl unblocks DI registration;
        //   biometric availability is never read on those targets
        //   (pair button gated at the call site anyway).
#if IOS
        builder.Services.AddSingleton<IBiometricsAvailability, Recto.Platforms.iOSImpl.IosBiometricsAvailability>();
#elif ANDROID
        builder.Services.AddSingleton<IBiometricsAvailability, Recto.Platforms.AndroidImpl.AndroidBiometricsAvailability>();
#else
        builder.Services.AddSingleton<IBiometricsAvailability, NullBiometricsAvailability>();
#endif

        // Recto.Shared scaffold: validators, handler scan, IBootloaderClient typed HttpClient.
        builder.Services.AddSharedServices(builder.Configuration, isClient: true);

        builder.Services.AddMauiBlazorWebView();

#if DEBUG
        builder.Services.AddBlazorWebViewDeveloperTools();
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
