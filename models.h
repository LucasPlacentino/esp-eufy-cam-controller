// from https://github.com/JanLoebel/eufy-node-client/blob/master/src/http/http-response.models.ts
struct Device {
  int device_id;
  bool is_init_complete;
  String device_sn;
  String device_name;
  String device_model;
  String time_zone;
  int device_type;
  int device_channel;
  Sting station_sn;
  String schedule;
  String schedulex;
  String wifi_mac;
  String sub1g_mac;
  String main_sw_version;
  String main_hw_version;
  String sec_sw_version;
  String sec_hw_version;
  int sector_id;
  int event_num;
  String wifi_ssid;
  String ip_addr;
  int main_sw_time;
  int sec_sw_time;
  int bind_time;
  String cover_path;
  int cover_time;
  String local_ip;
  String language;
  String sku_number;
  String lot_number;
  int create_time;
  int update_time;
  int status;
};

struct Parameter {
  int param_id;
  String station_sn;
  int param_type;
  String param_value;
  int create_time;
  int update_time;
  int status;
}

/*
struct LoginResult {
  user_id: string;
  email: string;
  nick_name: string;
  auth_token: string;
  token_expires_at: number;
  avatar: string;
  invitation_code: string;
  inviter_code: string;
  verify_code_url: string;
  mac_addr: string;
  domain: string;
  ab_code: string;
  geo_key: string;
  privilege: number;
  phone: string;
  phone_code: string;
  params: any;
  trust_list: Array<any>;
}
*/


/*

export interface DskKey {
  enabled: boolean;
  dsk_keys: Array<{
    station_sn: string;
    dsk_key: string;
    expiration: number;
    about_to_be_replaced: boolean;
  }>;
}

*/
