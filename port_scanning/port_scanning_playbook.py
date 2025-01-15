import requests
import time

THEHIVE_URL = ""
THEHIVE_API_KEY = ""

# Cortex Connector ID
CORTEX_CONNECTOR_ID = ""

# 포트 스캐닝 감지 IP
detected_ip = "141.105.71.82"


def get_analyzer_id_by_name(analyzer_name):
    url = f"{THEHIVE_URL}/api/connector/cortex/analyzer"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}"
    }
    resp = requests.get(url, headers=headers, verify=False)
    if resp.status_code == 200:
        analyzers = resp.json()
        for analyzer in analyzers:
            if analyzer.get("name") == analyzer_name:
                return analyzer.get("id")
        print(f"[-] '{analyzer_name}'이라는 이름의 아날라이저를 찾지 못했습니다.")
        return None
    else:
        print(f"[-] 아날라이저 목록 조회 실패: {resp.status_code}")
        print(resp.text)
        return None


def get_responder_id_by_name(entity_type, entity_id, responder_name):
    url = f"{THEHIVE_URL}/api/connector/cortex/responder/{entity_type}/{entity_id}"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}"
    }
    resp = requests.get(url, headers=headers, verify=False)
    if resp.status_code == 200:
        responders = resp.json()
        for r in responders:
            if r.get("name") == responder_name:
                return r.get("id")
        print(f"[-] '{responder_name}'라는 이름의 responder를 찾지 못했습니다.")
        return None
    else:
        print(f"[-] Responder 목록 조회 실패: {resp.status_code}")
        print(resp.text)
        return None


def create_thehive_case(ip_address):
    case_payload = {
        "title": f"[PortScan] Detected from {ip_address}",
        "description": f"Port scanning detected from IP {ip_address}.",
        "severity": 3,
        "tags": ["port_scanning", "auto-detected"],
        "flag": False,
        "tlp": 2,
        "pap": 2,
        "tasks": [
            {
                "title": "Analyze IP with VirusTotal",
                "description": "Use VirusTotal to check the IP reputation"
            },
            {
                "title": "Monitor IP Activity",
                "description": "Monitor the IP activity for 3 Days"
            },
            {
                "title": "Block IP in Firewall",
                "description": "Block the malicious IP in the firewall"
            },
            {
                "title": "Document and Close Case",
                "description": "Document all relevant info and close the case"
            }
        ]
    }
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{THEHIVE_URL}/api/v1/case"
    response = requests.post(url, json=case_payload, headers=headers, verify=False)

    if response.status_code == 201:
        case_id = response.json().get("_id")
        print(f"[+] Case 생성 성공! case_id={case_id}")
        return case_id
    else:
        print(f"[-] Case 생성 실패: {response.status_code}")
        print(response.text)
        return None


def add_observable_to_case(case_id, ip_address):
    obs_payload = {
        "dataType": "ip",
        "data": ip_address,
        "tlp": 2,
        "pap": 2,
        "message": f"Port scanning activity from {ip_address}."
    }
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{THEHIVE_URL}/api/v1/case/{case_id}/observable"
    response = requests.post(url, json=obs_payload, headers=headers, verify=False)

    if response.status_code == 201:
        created_obs = response.json()
        if isinstance(created_obs, list) and len(created_obs) > 0:
            obs_id = created_obs[0].get("_id")
            print(f"[+] Observable(IP) 생성 성공: obs_id={obs_id}")
            return obs_id
        print("[!] Observable 생성 응답이 예상과 다릅니다.")
        return None
    else:
        print(f"[-] Observable 생성 실패: {response.status_code}")
        print(response.text)
        return None


def run_analyzer_on_observable(analyzer_id, observable_id):
    if not analyzer_id:
        print("[-] analyzer_id가 없습니다. 분석 불가.")
        return None

    url = f"{THEHIVE_URL}/api/connector/cortex/job"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "analyzerId": analyzer_id,
        "cortexId": CORTEX_CONNECTOR_ID,
        "artifactId": observable_id
    }

    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code == 201:
        job_info = response.json()
        job_id = job_info.get("_id")
        print(f"[+] 아날라이저 실행 Job 생성 성공! job_id={job_id}")
        return job_id
    else:
        print(f"[-] 아날라이저 실행 실패: {response.status_code}")
        print(response.text)
        return None


def run_responder_on_case(responder_id, case_id):
    url = f"{THEHIVE_URL}/api/connector/cortex/action"
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "responderId": responder_id,
        "cortexId": CORTEX_CONNECTOR_ID,
        "objectType": "case",
        "objectId": case_id,
        "parameters": {
            "message": "Blocking IP due to port scanning detection."
        },
        "tlp": 2
    }
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    if resp.status_code == 200:
        action_info = resp.json()
        action_id = action_info.get("_id")
        print(f"[+] Responder 실행 성공! action_id={action_id}")
        return action_id
    else:
        print(f"[-] Responder 실행 실패: {resp.status_code}")
        print(resp.text)
        return None


def add_mitre_ttp_to_case(case_id):
    procedure_payload = {
        "patternId": "T1046",
        "tactic": "Discovery",
        "occurDate": int(time.time() * 1000),
        "description": (
            "Adversaries may attempt to get a listing of services running on remote hosts.\n"
            "관련 MITRE ATT&CK 정보: Network Service Discovery (T1046)."
        )
    }
    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }
    url = f"{THEHIVE_URL}/api/v1/case/{case_id}/procedure"
    response = requests.post(url, json=procedure_payload, headers=headers, verify=False)

    if response.status_code == 201:
        proc_id = response.json().get("_id")
        print(f"[+] TTP(T1046) 추가 성공: procedure_id={proc_id}")
        return proc_id
    else:
        print(f"[-] TTP 추가 실패: {response.status_code}")
        print(response.text)
        return None


if __name__ == "__main__":
    print(f"[!] 포트 스캐닝 감지: {detected_ip}")

    # 1) 사건 생성
    case_id = create_thehive_case(detected_ip)
    if not case_id:
        print("[-] 사건 생성 실패. 워크플로 중단.")
        exit(1)

    # 2) 옵저버블(IP) 추가
    observable_id = add_observable_to_case(case_id, detected_ip)
    if not observable_id:
        print("[-] 옵저버블 생성 실패. 워크플로 중단.")
        exit(1)

    # 3) TheHive에서 'VirusTotal_GetReport_3_1' 아날라이저의 ID 조회
    vt_analyzer_name = "VirusTotal_GetReport_3_1"
    vt_analyzer_id = get_analyzer_id_by_name(vt_analyzer_name)

    # 4) 옵저버블에 대해 아날라이저 실행
    job_id = run_analyzer_on_observable(vt_analyzer_id, observable_id)
    if job_id:
        print(f"[+] {vt_analyzer_name} 아날라이저 실행 완료 (JobID={job_id})")
    else:
        print(f"[-] {vt_analyzer_name} 아날라이저 실행 실패.")

    # target_responder_name = "Virustotal_Downloader_0_1"
    # vtdl_responder_id = get_responder_id_by_name("case", case_id, target_responder_name)

    vtdl_responder_id = "7141c136ce273c28ab3fedf1e1dcbb08"
    # if vtdl_responder_id:
    #     print(f"[+] Responder '{target_responder_name}' ID={vtdl_responder_id}")
    # else:
    #     print(f"[-] {target_responder_name} responder를 찾지 못했습니다.")

    action_id = run_responder_on_case(vtdl_responder_id, case_id)
    if action_id:
        print(f"[+] Responder 실행 완료 (ActionID={action_id}).")
    else:
        print("[-] Responder 실행 실패.")

    # 6) 사건에 MITRE ATT&CK TTP (T1046) 추가
    ttp_id = add_mitre_ttp_to_case(case_id)
    if ttp_id:
        print("[+] 사건에 MITRE ATT&CK Technique 정보가 추가되었습니다.")
    else:
        print("[-] TTP 추가 실패.")

    print("[+] 전체 워크플로 완료.")
