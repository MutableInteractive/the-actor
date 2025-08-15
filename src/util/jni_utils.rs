use jni::JNIEnv;
use jni::objects::{JObject, JString};

pub fn get_string(env: &mut JNIEnv, jobject: &JObject, field: &str) -> String{
    let jstr: JString = env.get_field(jobject, field, "Ljava/lang/String;")
        .unwrap().l().unwrap().into();
    env.get_string(&jstr).unwrap().into()
}

pub fn get_i32(env: &mut JNIEnv, jobject: &JObject, field: &str) -> i32 {
    env.get_field(jobject, field, "I").unwrap().i().unwrap()
}

pub fn get_i64(env: &mut JNIEnv, jobject: &JObject, field: &str) -> i64 {
    env.get_field(jobject, field, "J").unwrap().j().unwrap()
}

pub fn get_i16(env: &mut JNIEnv, jobject: &JObject, field: &str) -> i16 {
    env.get_field(jobject, field, "S").unwrap().s().unwrap()
}