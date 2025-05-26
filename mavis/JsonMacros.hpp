#pragma once

#define JSON_IT_KEY(it) ((it).key())
#define JSON_IT_VAL(it) ((it).value())

#ifdef USE_NLOHMANN_JSON
  #define JSON_GET(obj, key, type) ((obj).at(key).get<type>())
  #define JSON_GET_BOOL(val) (val).get<bool>()
  #define JSON_CAST(value, type) ((value).get<type>())
  #define JSON_VALUE_TO(T, obj) json::value_to<T>(obj)
  #define JSON_AS_STRING(obj) ((obj).get<std::string>())
  #define JSON_IS_ARRAY(obj) ((obj).is_array())
  #define JSON_IS_OBJECT(obj) ((obj).is_object())
#else
  #define JSON_GET(obj, key, type) (boost::json::value_to<type>((obj).at(key)))
  #define JSON_GET_BOOL(val) (val).as_bool()
  #define JSON_CAST(value, type) (boost::json::value_to<type>(value))
  #define JSON_VALUE_TO(T, obj) boost::json::value_to<T>(obj)
  #define JSON_AS_STRING(obj) ((obj).as_string())
  #define JSON_IS_ARRAY(obj) ((obj).is_array())
  #define JSON_IS_OBJECT(obj) ((obj).is_object())
#endif
