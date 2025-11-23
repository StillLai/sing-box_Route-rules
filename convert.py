import pandas as pd
import concurrent.futures
import os
import json
import requests
import yaml
import ipaddress

def read_yaml_from_url(url):
    response = requests.get(url)
    response.raise_for_status()
    yaml_data = yaml.safe_load(response.text)
    return yaml_data

def read_list_from_url(url):
    df = pd.read_csv(url, header=None, names=['pattern', 'address', 'other'], on_bad_lines='warn')
    return df

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                line_content = lines[0]
                items = line_content.split()
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    if is_ipv4_or_ipv6(item):
                        pattern = 'IP-CIDR'
                    else:
                        if address.startswith('+') or address.startswith('.'):
                            pattern = 'DOMAIN-SUFFIX'
                            address = address[1:]
                            if address.startswith('.'):
                                address = address[1:]
                        else:
                            pattern = 'DOMAIN'
                else:
                    pattern, address = item.split(',', 1)  
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df = read_list_from_url(link)
    else:
        df = read_list_from_url(link)
    return df

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(parse_and_convert_to_dataframe, [link]))
        df = pd.concat(results, ignore_index=True)

    df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)

    # 恢复原始映射字典，但处理重复键的情况
    map_dict = {
        'DOMAIN-SUFFIX': 'domain_suffix', 
        'HOST-SUFFIX': 'domain_suffix', 
        'DOMAIN': 'domain', 
        'HOST': 'domain', 
        'host': 'domain',
        'DOMAIN-KEYWORD': 'domain_keyword', 
        'HOST-KEYWORD': 'domain_keyword', 
        'host-keyword': 'domain_keyword', 
        'IP-CIDR': 'ip_cidr',
        'ip-cidr': 'ip_cidr', 
        'IP-CIDR6': 'ip_cidr', 
        'IP6-CIDR': 'ip_cidr',
        'SRC-IP-CIDR': 'source_ip_cidr', 
        'GEOIP': 'geoip', 
        'DST-PORT': 'port',
        'SRC-PORT': 'source_port', 
        'URL-REGEX': 'domain_regex', 
        'PROCESS-NAME': 'process_name'
    }
    
    # 处理重复键：PROCESS-NAME映射到package_name
    # 创建一个新的DataFrame来处理重复映射
    df_filtered = df[df['pattern'].isin(map_dict.keys())].reset_index(drop=True)
    
    # 创建处理重复映射的DataFrame
    duplicate_mappings = []
    for pattern in df_filtered['pattern'].unique():
        if pattern == 'PROCESS-NAME':
            # 对于PROCESS-NAME，创建两个映射
            duplicate_mappings.append({'pattern': pattern, 'mapped_pattern': 'process_name'})
            duplicate_mappings.append({'pattern': pattern, 'mapped_pattern': 'package_name'})
        else:
            # 对于其他模式，使用正常映射
            duplicate_mappings.append({'pattern': pattern, 'mapped_pattern': map_dict[pattern]})
    
    mapping_df = pd.DataFrame(duplicate_mappings)
    
    # 合并原始数据和映射
    df_with_mappings = pd.merge(df_filtered, mapping_df, on='pattern')
    
    df_with_mappings = df_with_mappings.drop_duplicates().reset_index(drop=True)

    os.makedirs(output_directory, exist_ok=True)

    result_rules = {"version": 3, "rules": []}
    domain_entries = []

    # 按映射后的模式分组处理
    for pattern, group in df_with_mappings.groupby('mapped_pattern'):
        addresses = group['address'].tolist()
        
        if pattern == 'domain_suffix':
            rule_entry = {pattern: ['.' + address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
            domain_entries.extend([address.strip() for address in addresses])
        elif pattern == 'domain':
            domain_entries.extend([address.strip() for address in addresses])
        elif pattern in ['port', 'source_port']:
            # 特殊处理端口字段，将端口号转换为数字
            port_numbers = []
            for address in addresses:
                address = address.strip()
                try:
                    # 尝试将端口号转换为整数
                    port_numbers.append(int(address))
                except ValueError:
                    # 如果转换失败，保持原样（可能是端口范围或其他格式）
                    port_numbers.append(address)
            rule_entry = {pattern: port_numbers}
            result_rules["rules"].append(rule_entry)
        else:
            rule_entry = {pattern: [address.strip() for address in addresses]}
            result_rules["rules"].append(rule_entry)
            
    domain_entries = list(set(domain_entries))
    if domain_entries:
        result_rules["rules"].insert(0, {'domain': domain_entries})

    file_name = os.path.join(output_directory, f"{os.path.basename(link).split('.')[0]}.json")
    
    # 自定义 JSON 编码器，确保端口数字不被转换为字符串
    class PortNumberEncoder(json.JSONEncoder):
        def encode(self, obj):
            if isinstance(obj, dict):
                return '{' + ', '.join(f'"{k}": {self.encode(v)}' for k, v in obj.items()) + '}'
            elif isinstance(obj, list):
                return '[' + ', '.join(self.encode(item) for item in obj) + ']'
            elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
                return str(obj)
            else:
                return super().encode(obj)
    
    with open(file_name, 'w', encoding='utf-8') as output_file:
        json.dump(sort_dict(result_rules), output_file, ensure_ascii=False, indent=2, cls=PortNumberEncoder)

    srs_path = file_name.replace(".json", ".srs")
    os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
    return file_name

with open("../source.txt", 'r') as links_file:
    links = links_file.read().splitlines()

links = [l for l in links if l.strip() and not l.strip().startswith("#")]

output_dir = "./"
result_file_names = []

for link in links:
    result_file_name = parse_list_file(link, output_directory=output_dir)
    result_file_names.append(result_file_name)

for file_name in result_file_names:
    print(file_name)