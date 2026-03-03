#!/usr/bin/env python3

import configparser
import questionary


class Config(object):
    def __init__(self, conf_file) -> None:
        print("Config constructor")
        self.config = configparser.ConfigParser(allow_no_value=True)
        self.config.read(conf_file)
        self.conf_file = conf_file

    def get_bps_ip(self):
        para1, para2 = 'BPS', 'bps_system'
        msg = "BreakingPoint System IP?"
        while True:
            value = self.config[para1][para2] if self.config[para1][para2] != "" else questionary.password(msg).ask()
            if value != "":
                break
            print("Please use the enter/return {}".format(msg))
            self.set_config_value(para1, para2, value)
        return value

    def set_bp_ip(self, value):
        para1, para2 = 'BPS', 'bps_system'
        self.set_config_value(para1, para2, value)

    def get_bps_user(self):
        para1, para2 = 'BPS', 'bpsuser'
        msg = "BreakingPoint User name?"
        while True:
            value = self.config[para1][para2] if self.config[para1][para2] != "" else questionary.password(msg).ask()
            if value != "":
                break
            print("Please use the enter/return {}".format(msg))
            self.set_config_value(para1, para2, value)
        return value

    def set_bp_user(self, value):
        para1, para2 = 'BPS', 'bpsuser'
        self.set_config_value(para1, para2, value)

    def get_bps_pwd(self):
        para1, para2 = 'BPS', 'bpspass'
        msg = "BreakingPoint User password?"
        while True:
            value = self.config[para1][para2] if self.config[para1][para2] != "" else questionary.password(msg).ask()
            if value != "":
                break
            print("Please use the enter/return {}".format(msg))
            self.set_config_value(para1, para2, value)
        return value

    def set_bp_pwd(self, value):
        para1, para2 = 'BPS', 'bpspass'
        self.set_config_value(para1, para2, value)

    def get_search_strikes(self):
        para1, para2 = 'SEARCH', 'search_strikes'
        msg = "BreakingPoint search strikes?"
        while True:
            value = self.config[para1][para2] if self.config[para1][para2] != "" else questionary.password(msg).ask()
            if value != "":
                break
            print("Please use the enter/return {}".format(msg))
            self.set_config_value(para1, para2, value)
        return value

    def set_search_strikes(self, value):
        para1, para2 = 'SEARCH', 'search_strikes'
        self.set_config_value(para1, para2, value)

    def set_number_of_filter(self, value):
        para1, para2 = 'SEARCH', 'number_of_filter'
        self.set_config_value(para1, para2, value)

    def get_number_of_filter(self):
        return int(self.check_empty_para('SEARCH', 'number_of_filter'))

    def get_test_name(self):
        return self.check_empty_para('VAR', 'test')

    def get_import_test_file(self):
        return self.check_empty_para('VAR', 'import_test_file')

    def get_new_strike_list_name(self):
        return self.check_empty_para('VAR', 'new_strike_list_name')

    def get_new_cve_list_file(self):
        return self.check_empty_para('VAR', 'new_cve_list_file')

    def get_dv_filters_list_file(self):
        return self.check_empty_para('VAR', 'dv_filters_list_file')

    def get_pcaps_folder(self):
        return self.check_empty_para('VAR', 'pcaps_folder')

    def get_tracker_file(self):
        return self.check_empty_para('VAR', 'tracker_file')

    def get_no_filter_found_file(self):
        return self.check_empty_para('VAR', 'no_filter_found_file')

    def get_artefact_folder(self):
        return self.check_empty_para('VAR', 'artefacts_folder')

    def get_dep_path(self):
        return self.check_empty_para('DEP', 'path')

    def get_tool(self):
        return self.check_empty_para('DEP', 'tool')

    def get_pcap_name(self):
        return self.check_empty_para('DEP', 'pcap_name')

    def set_access_key_id(self, value):
        para1, para2 = 'AWS', 'access_key_id'
        self.set_config_value(para1, para2, value)

    def get_access_key_id(self):
        return self.check_empty_para('AWS', 'access_key_id')

    def set_secret_key(self, value):
        para1, para2 = 'AWS', 'secret_key'
        self.set_config_value(para1, para2, value)

    def get_secret_key(self):
        return self.check_empty_para('AWS', 'secret_key')

    def set_bucket_name(self, value):
        para1, para2 = 'AWS', 'bucket_name'
        self.set_config_value(para1, para2, value)

    def get_bucket_name(self):
        return self.check_empty_para('AWS', 'bucket_name')

    def get_bucket_prefix(self):
        return self.check_empty_para('AWS', 'prefix')

    def get_tracker_file_url(self):
        return self.check_empty_para('AWS', 'tracker_file_url')

    def get_no_filter_cve_url(self):
        return self.check_empty_para('AWS', 'no_filter_cve_url')

    def get_pcaps_folder_url(self):
        return self.check_empty_para('AWS', 'pcaps_folder_url')

    def check_empty_para(self, para1, para2):
        value = self.config[para1][para2]
        # print("{}-{}: {}".format(para1, para2, value))
        for retry in range(1, 4):
            if value != "":
                return value
            else:
                value = input("Please enter {}-{} parameter-> ".format(para1, para2))
                self.config.set(para1, para2, value)
                with open(self.conf_file, 'w') as configfile:
                    self.config.write(configfile)
        raise Exception("Section {}, parameter {} not found!\nPlease furnish the config file and " \
                        "Re-Run the code".format(para1, para2))

    def set_config_value(self, para1, para2, value):
        self.config.set(para1, para2, value)
        with open(self.conf_file, 'w') as configfile:
            self.config.write(configfile)



if __name__ == '__main__':
    conf_file = "config/.config.ini"
    conf = Config(conf_file)