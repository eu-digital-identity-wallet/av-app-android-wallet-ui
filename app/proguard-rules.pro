-dontwarn com.fasterxml.jackson.dataformat.xml.JacksonXmlModule
-dontwarn com.fasterxml.jackson.dataformat.xml.XmlMapper
-dontwarn com.sun.org.apache.xml.internal.utils.PrefixResolver
-dontwarn com.sun.org.apache.xpath.internal.XPathContext
-dontwarn java.beans.BeanInfo
-dontwarn java.beans.ConstructorProperties
-dontwarn java.beans.IndexedPropertyDescriptor
-dontwarn java.beans.IntrospectionException
-dontwarn java.beans.Introspector
-dontwarn java.beans.MethodDescriptor
-dontwarn java.beans.PropertyDescriptor
-dontwarn java.beans.Transient
-dontwarn javax.script.ScriptEngine
-dontwarn javax.script.ScriptEngineManager
-dontwarn javax.swing.tree.TreeNode
-dontwarn org.apache.xml.utils.PrefixResolver
-dontwarn org.apache.xpath.XPathContext
-dontwarn org.jaxen.FunctionContext
-dontwarn org.jaxen.NamespaceContext
-dontwarn org.jaxen.Navigator
-dontwarn org.jaxen.VariableContext
-dontwarn org.jaxen.XPathFunctionContext
-dontwarn org.jaxen.dom.DocumentNavigator
-dontwarn org.jetbrains.dokka.CoreExtensions
-dontwarn org.jetbrains.dokka.DokkaConfiguration$DokkaModuleDescription
-dontwarn org.jetbrains.dokka.DokkaConfiguration$DokkaSourceSet
-dontwarn org.jetbrains.dokka.DokkaConfiguration$PluginConfiguration
-dontwarn org.jetbrains.dokka.DokkaConfiguration$SerializationFormat
-dontwarn org.jetbrains.dokka.DokkaConfiguration
-dontwarn org.jetbrains.dokka.DokkaSourceSetID
-dontwarn org.jetbrains.dokka.Platform
-dontwarn org.jetbrains.dokka.analysis.kotlin.internal.DocumentableSourceLanguageParser
-dontwarn org.jetbrains.dokka.analysis.kotlin.internal.InternalKotlinAnalysisPlugin
-dontwarn org.jetbrains.dokka.analysis.kotlin.internal.ModuleAndPackageDocumentationReader
-dontwarn org.jetbrains.dokka.analysis.kotlin.internal.SampleProviderFactory
-dontwarn org.jetbrains.dokka.generation.Generation
-dontwarn org.jetbrains.dokka.links.Callable
-dontwarn org.jetbrains.dokka.links.DRI
-dontwarn org.jetbrains.dokka.links.DriTarget
-dontwarn org.jetbrains.dokka.model.Annotations$Annotation
-dontwarn org.jetbrains.dokka.model.Annotations$AnnotationScope
-dontwarn org.jetbrains.dokka.model.DisplaySourceSet
-dontwarn org.jetbrains.dokka.model.DisplaySourceSetKt
-dontwarn org.jetbrains.dokka.model.ExtraModifiers$KotlinOnlyModifiers$External
-dontwarn org.jetbrains.dokka.model.ExtraModifiers$KotlinOnlyModifiers$TailRec
-dontwarn org.jetbrains.dokka.model.ExtraModifiers$KotlinOnlyModifiers
-dontwarn org.jetbrains.dokka.model.JavaModifier$Final
-dontwarn org.jetbrains.dokka.model.JavaVisibility$Public
-dontwarn org.jetbrains.dokka.model.KotlinModifier$Final
-dontwarn org.jetbrains.dokka.model.KotlinVisibility$Public
-dontwarn org.jetbrains.dokka.model.Modifier
-dontwarn org.jetbrains.dokka.model.Visibility
-dontwarn org.jetbrains.dokka.model.WithChildren
-dontwarn org.jetbrains.dokka.pages.RendererSpecificResourcePage
-dontwarn org.jetbrains.dokka.pages.RenderingStrategy$Copy
-dontwarn org.jetbrains.dokka.pages.RenderingStrategy
-dontwarn org.jetbrains.dokka.plugability.ConfigurableBlock
-dontwarn org.jetbrains.dokka.plugability.DokkaContext
-dontwarn org.jetbrains.dokka.plugability.DokkaPlugin$ExtensionProvider
-dontwarn org.jetbrains.dokka.plugability.DokkaPlugin
-dontwarn org.jetbrains.dokka.plugability.DokkaPluginKt
-dontwarn org.jetbrains.dokka.plugability.ExtendingDSL
-dontwarn org.jetbrains.dokka.plugability.Extension
-dontwarn org.jetbrains.dokka.plugability.ExtensionPoint
-dontwarn org.jetbrains.dokka.plugability.OrderDsl
-dontwarn org.jetbrains.dokka.renderers.PostAction
-dontwarn org.jetbrains.dokka.renderers.Renderer
-dontwarn org.jetbrains.dokka.transformers.documentation.DocumentableMerger
-dontwarn org.jetbrains.dokka.transformers.documentation.DocumentableToPageTranslator
-dontwarn org.jetbrains.dokka.transformers.documentation.DocumentableTransformer
-dontwarn org.jetbrains.dokka.transformers.documentation.PreMergeDocumentableTransformer
-dontwarn org.jetbrains.dokka.transformers.pages.PageTransformer
-dontwarn org.jetbrains.dokka.utilities.DokkaLogger
-dontwarn org.jetbrains.dokka.utilities.JsonKt
-dontwarn org.jetbrains.dokka.utilities.TypeReference$Companion
-dontwarn org.jetbrains.dokka.utilities.TypeReference
-dontwarn org.python.core.Py
-dontwarn org.python.core.PyDictionary
-dontwarn org.python.core.PyFloat
-dontwarn org.python.core.PyInteger
-dontwarn org.python.core.PyLong
-dontwarn org.python.core.PyNone
-dontwarn org.python.core.PyObject
-dontwarn org.python.core.PySequence
-dontwarn org.python.core.PyStringMap
-dontwarn org.python.core.PySystemState
-dontwarn org.zeroturnaround.javarebel.ClassEventListener
-dontwarn org.zeroturnaround.javarebel.Reloader
-dontwarn org.zeroturnaround.javarebel.ReloaderFactory
-dontwarn com.eygraber.uri.JvmUriKt
-dontwarn org.slf4j.impl.StaticLoggerBinder
-dontwarn org.slf4j.impl.StaticMDCBinder
-dontwarn org.koin.androidx.viewmodel.GetViewModelKt
-dontwarn org.koin.compose.stable.StableHoldersKt
-dontwarn org.koin.compose.stable.StableParametersDefinition
-dontwarn okhttp3.internal.Util

# Google Crypto Tink
-dontwarn com.google.crypto.tink.subtle.Ed25519Sign$KeyPair
-dontwarn com.google.crypto.tink.subtle.Ed25519Sign
-dontwarn com.google.crypto.tink.subtle.Ed25519Verify
-dontwarn com.google.crypto.tink.subtle.X25519
-dontwarn com.google.crypto.tink.subtle.XChaCha20Poly1305

# Couroutines
-keep,allowobfuscation,allowshrinking class kotlin.coroutines.Continuation

# API Models
-keep class eu.europa.ec.networklogic.model.** { *; }

# Enum
-keep enum * { *; }

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-keep class sun.misc.Unsafe { *; }
-keep class com.google.gson.** { *; }

# Keep all config classes and their fields for Gson serialization
-keep class * implements eu.europa.ec.uilogic.serializer.UiSerializable { *; }
-keep class * implements eu.europa.ec.uilogic.serializer.UiSerializableParser { *; }
-keep class * implements eu.europa.ec.uilogic.serializer.adapter.SerializableAdapterType { *; }

# Keep all config-related classes
-keep class eu.europa.ec.commonfeature.config.** { *; }
-keep class eu.europa.ec.onboardingfeature.config.** { *; }
-keep class eu.europa.ec.uilogic.config.** { *; }
-keep class eu.europa.ec.uilogic.navigation.** { *; }
-keep class eu.europa.ec.uilogic.component.** { *; }

# Keep DocumentId for serialization
-keep class eu.europa.ec.eudi.wallet.document.DocumentExtensions { *; }

# UI Config interfaces
-keep interface eu.europa.ec.uilogic.serializer.UiSerializableParser
-keep interface eu.europa.ec.uilogic.serializer.UiSerializable

# Bouncycastle
-keep class org.bouncycastle.** { *; }
-keep class org.bouncycastle.jce.provider.BouncyCastleProvider { *; }

# Core Libs
-keep class com.nimbusds.jwt.**{ *; }
-keep class com.nimbusds.jose.**{ *; }

# NFC/Passport Scanning Libraries (JMRTD, SCUBA)
-keep class org.jmrtd.** { *; }
-keep class net.sf.scuba.** { *; }
-keep class org.ejbca.cvc.** { *; }
-dontwarn org.jmrtd.**
-dontwarn net.sf.scuba.**
-dontwarn org.ejbca.cvc.**

# Koin
-keep class org.koin.** { *; }
-keep class org.koin.core.** { *; }
-keep class org.koin.android.** { *; }
-keepclassmembers class * {
    @org.koin.core.annotation.* *;
    @org.koin.android.annotation.* *;
}

# Koin Annotations - Keep all classes annotated with Koin annotations
-keep @org.koin.core.annotation.* class * { *; }
-keep @org.koin.android.annotation.* class * { *; }

# Keep Koin generated modules
-keep class * extends org.koin.core.module.Module { *; }

# Keep ViewModels and their constructors
-keep class * extends androidx.lifecycle.ViewModel {
    <init>(...);
}

# Keep all injected parameters
-keepclassmembers class * {
    @org.koin.core.annotation.InjectedParam *;
}

# Ensure Koin definitions are preserved
-if class *
-keepclasseswithmembers class <1> {
    @org.koin.core.annotation.Single <methods>;
}

-if class *
-keepclasseswithmembers class <1> {
    @org.koin.core.annotation.Factory <methods>;
}

# Strip android.util.Log calls in release (R8 assumenosideeffects)
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int d(...);
    public static int i(...);
}

# Strip Timber d/i/v call sites in release (R8 assumenosideeffects)
-assumenosideeffects class timber.log.Timber {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Face Matching SDK (JNI)
# Keep all classes used by native code to prevent obfuscation/removal
-keep class kl.open.fmandroid.** { *; }
-keepclassmembers class kl.open.fmandroid.** {
    <init>(...);
    *;
}
# Specifically keep ProcessResult and NativeBridge for JNI
-keep class kl.open.fmandroid.ProcessResult {
    <init>(...);
    *;
}
-keep class kl.open.fmandroid.NativeBridge {
    native <methods>;
    *;
}

# ML Kit Text Recognition rules
-keep class com.google.mlkit.** { *; }
-keep class com.google.android.gms.internal.mlkit_vision_** { *; }
-keep class com.google.android.gms.internal.mlkit_common.** { *; }
-keep class com.google.android.libraries.vision.visionkit.** { *; }
-keep class com.google.android.gms.dynamite.descriptors.com.google.mlkit.dynamite.** { *; }
-keep class com.google.android.gms.common.internal.safeparcel.SafeParcelable {
    public static final *** CREATOR;
}
-keep public class com.google.android.gms.common.internal.ReflectedParcelable
-keep public class * extends com.google.android.gms.common.internal.ReflectedParcelable
-keep public class * implements com.google.android.gms.common.internal.ReflectedParcelable

-keep class com.google.android.gms.common.annotation.KeepName { *; }
-keepnames class * {
    @com.google.android.gms.common.annotation.KeepName *;
}
-keepclassmembernames class * {
    @com.google.android.gms.common.annotation.KeepName *;
}

-dontwarn com.google.android.gms.**
-dontwarn com.google.mlkit.**

# MRZ parser instantiates record classes via reflection
# (MrzFormat.newRecord -> recordClass.getDeclaredConstructor().newInstance())
-keep class eu.europa.ec.passportscanner.parser.MrzRecord { <init>(...); }
-keep class eu.europa.ec.passportscanner.parser.records.** { <init>(...); <fields>; }
