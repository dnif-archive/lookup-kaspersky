from base64 import b64encode
import requests
import yaml
import requests
import datetime
import os
import json
import sys
import logging

path = os.environ["WORKDIR"]
try:
    with open(path + "/lookup_plugins/kaspersky/dnifconfig.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
        ks_cert_path=path+cfg['lookup_plugin']['KASPERSKY_API_CERT_PATH']
        ks_cred= b64encode(("{0}:{1}").format(cfg['lookup_plugin']['KASPERSKY_API_USERNAME'],cfg['lookup_plugin']['KASPERSKY_API_PASSWORD']))
        headers = {'Authorization': 'Basic %s' % ks_cred}
except Exception ,e:
    logging.warning("Error in reading KasperSky dnifconfig >>{}<<".format(e))

def get_hash_report(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/hash/'+str(i[var_array[0]])
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
                logging.warning('Api Request Error %s' %e)
            try:
                if json_response['FileGeneralInfo']['HitsCount'] != None:
                    i['$KLHits']= json_response['FileGeneralInfo']['HitsCount']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['FirstSeen'] !=None:
                    i['$KLFirstSeen'] = json_response['FileGeneralInfo']['FirstSeen']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['LastSeen'] !=None:
                    i['$KLLastSeen'] = json_response['FileGeneralInfo']['LastSeen']
            except Exception:
                pass
            try:
               if json_response['FileGeneralInfo']['Md5'] !=None and json_response['FileGeneralInfo']['Md5']!=[]:
                    i['$KLMd5'] = json_response['FileGeneralInfo']['Md5']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['Sha1'] !=None and json_response['FileGeneralInfo']['Sha1']!=[]:
                    i['$KLSha1'] = json_response['FileGeneralInfo']['Sha1']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['Sha256']!=None and json_response['FileGeneralInfo']['Sha256']!=[]:
                    i['$KLSha256'] = json_response['FileGeneralInfo']['Sha256']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['Type']!=None and json_response['FileGeneralInfo']['Type']!=[]:
                    i['$KLFormat'] = json_response['FileGeneralInfo']['Type']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['Size'] !=None and json_response['FileGeneralInfo']['Size']!=[]:
                    i['$KLSize'] = json_response['FileGeneralInfo']['Size']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['Signer'] !=None and json_response['FileGeneralInfo']['Signer']!=[]:
                    i['$KLSigner'] = json_response['FileGeneralInfo']['Signer']
            except Exception:
                pass
            try:
                if json_response['FileGeneralInfo']['Packer']!=None and json_response['FileGeneralInfo']['Packer']!=[]:
                    i['$KLPacker'] = json_response['FileGeneralInfo']['Packer']
            except Exception:
                pass
            try:
                det_name= []
                for dname in json_response['DetectionsInfo']:
                    if dname['DetectionName']!=None and dname['DetectionName']!=[]:
                        det_name.append(dname['DetectionName'])
                i['$KLDetectionNames'] = list(set(det_name))
            except Exception:
                pass
            try:
                desc_url= []
                for dname in json_response['DetectionsInfo']:
                    if dname['DescriptionUrl']!=[] and dname['DescriptionUrl']!=None:
                        desc_url.append(dname['DescriptionUrl'])
                i['$KLDescriptionURL'] = list(set(desc_url))
            except Exception:
                pass
            try:
                file_name = []
                for fname in json_response['FileNames']:
                    file_name.append(fname['FileNames'])
                i['$KLFileNames'] = list(set(file_name))
            except Exception:
                pass
            try:
                i['$KLZone'] = json_response['Zone']
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['FileAccessedUrls']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedFileAccessedURL'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenFileAccessedURL'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyFileAccessedURL'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowFileAccesedURL'] = list(set(fyellow))
            except Exception:
                pass
            try:
                i['$KLZone'] = json_response['Zone']
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['FileAccessedUrls']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Domain'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Domain'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Domain'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Domain'])
                if len(fred) > 0:
                    i['$KLRedFileAccessedDomain'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenFileAccessedDomain'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyFileAccessedDomain'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowFileAccesedDomain'] = list(set(fyellow))
            except Exception:
                pass
    return inward_array


def get_ip_report_file(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/ip/'+str(i[var_array[0]])+'?sections=FilesDownloadedFromIp,HostedUrls'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('KasperSky Api Request Error %s' %e)
            try:
                hst_urls=[]
                for hsturl in json_response['HostedUrls']:
                    hst_urls.append(hsturl['Url'])
                i['$KLHostedURL'] = list(set(hst_urls))
            except Exception:
                pass
            try:
                fred=[]
                fgrey=[]
                fgreen=[]
                fyellow = []
                for zn in json_response['FilesDownloadedFromIp']:
                    if zn['Zone'] =='Red':
                        fred.append(zn['Md5'])
                    elif zn['Zone'] =='Grey':
                        fgrey.append(zn['Md5'])
                    elif zn['Zone'] =='Green':
                        fgreen.append(zn['Md5'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Md5'])
                if len(fred)>0:
                    i['$KLRedMd5'] =list(set(fred))
                if len(fgreen)>0:
                    i['$KLGreenMd5'] =list(set(fgreen))
                if len(fgrey)>0:
                    i['$KLGreyMd5'] =list(set(fgrey))
                if len(fyellow)>0:
                    i['$KLYellowMd5'] =list(set(fyellow))
            except Exception:
                pass
    return inward_array


def get_ip_report(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/ip/'+str(i[var_array[0]])+'?sections=IpDnsResolutions,IpGeneralInfo,IpWhoIs,Zone'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                derived = []
                drvres = []
                for drv in json_response['IpDnsResolutions']:
                    if drv['Categories'] != []:
                        derived.append(drv['Categories'])
                drvres = derived[0]
                for a in range(1, len(derived)):
                    drvres = list(set(drvres) | set(derived[a]))
                i['$KLIPDNSResolustionsCategories'] = drvres
            except Exception:
                pass
            try:
                dns_res=[]
                for doms in json_response['IpDnsResolutions']:
                    dns_res.append(doms['Domain'])
                i['$KLIPDNSResolustionsDomains'] =list(set(dns_res))
            except Exception:
                pass
            try:
                if json_response['IpGeneralInfo']['Categories']!=[]:
                    i['$KLCategory'] =json_response['IpGeneralInfo']['Categories']
            except Exception:
                pass
            try:
                if json_response['IpGeneralInfo']['FirstSeen']!=None:
                    i['$KLFirstSeen']=json_response['IpGeneralInfo']['FirstSeen']
            except Exception:
                pass
            try:
                if json_response['IpGeneralInfo']['HitsCount']!=None:
                    i['$KLHits']=json_response['IpGeneralInfo']['HitsCount']
            except Exception:
                pass
            try:
                if json_response['IpGeneralInfo']['ThreatScore']!=None:
                    i['$KLThreatScore'] = json_response['IpGeneralInfo']['ThreatScore']
            except Exception:
                pass
            try:
                i['$KLHasAdvancedPersistThreat'] = json_response['IpGeneralInfo']['HasApt']
            except Exception:
                pass
            try:
                if json_response['IpWhoIs']['Net']['Created']!=None:
                    i['$KLCreated']=json_response['IpWhoIs']['Net']['Created']
            except Exception:
                pass
            try:
                if json_response['IpWhoIs']['Net']['Changed']!=None:
                    i['$KLChanged'] = json_response['IpWhoIs']['Net']['Changed']
            except Exception:
                pass
            try:
                i['$KLIPRange'] = str(str(json_response['IpWhoIs']['Net']['StartIp'])+"-"+str(json_response['IpWhoIs']['Net']['EndIp']))
            except Exception:
                pass
            try:
                i['$KLNetname'] = json_response['IpWhoIs']['Net']['Name']
            except Exception:
                pass
            try:
                if json_response['IpWhoIs']['Net']['Description']!=None:
                    i['$KLNetDescription'] = json_response['IpWhoIs']['Net']['Description']
            except Exception:
                pass
            try:
                i['$KLZone'] = json_response['Zone']
            except Exception:
                pass
            try:
                asn=[]
                asd=[]
                for a in json_response['IpWhoIs']['Asn']:
                    if a['Origin']!=None:
                        asn.append(a['Origin'])
                    if a['Description']!=None:
                        asd.append(a['Description'])
                if asn != []:
                    i['$KLASN'] = asn
                if asd !=[]:
                    i['$KLASDescription'] = asd
            except Exception:
                pass
            try:
                role=[]
                for rl in json_response['IpWhoIs']['Contacts']:
                    role.append(rl['Role'])
                for r in json_response['IpWhoIs']['Contacts']:
                    if r['Role'] in role:
                        if r['Address']!=None:
                            i['$KL' + str(r['Role']).title()+'Address']=r['Address']
                        if r['Email']!=None:
                            i['$KL' + str(r['Role']).title() + 'Email'] = r['Email']
                        if r['Fax']!=None:
                            i['$KL' + str(r['Role']).title() + 'Fax'] = r['Fax']
                        if r['Name']!=None:
                            i['$KL' + str(r['Role']).title() + 'Name'] = r['Name']
                        if r['OrganizationId']!=None:
                            i['$KL' + str(r['Role']).title() + 'OrganizationId'] = r['OrganizationId']
                        if r['Phone']!=None:
                            i['$KL' + str(r['Role']).title() + 'Phone'] = r['Phone']
            except Exception:
                pass
    return inward_array


def get_domain_report(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/domain/'+str(i[var_array[0]])+'?sections=DomainGeneralInfo,DomainDnsResolutions,DomainWhoIsInfo,UrlReferrals,UrlReferredTo,Subdomains,Zone'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                if json_response['DomainGeneralInfo']['Categories']!=[]:
                    i['$KLCategories'] =list(set(json_response['DomainGeneralInfo']['Categories']))
            except Exception:
                pass
            try:
                if json_response['DomainGeneralInfo']['Domain'] !=None and json_response['DomainGeneralInfo']['Domain']!=[]:
                    i['$KLDomain'] = json_response['DomainGeneralInfo']['Domain']
            except Exception:
                pass
            try:
                if json_response['DomainGeneralInfo']['FilesCount'] != None:
                    i['$KLFilesCount'] = json_response['DomainGeneralInfo']['FilesCount']
            except Exception:
                pass
            try:
                if json_response['DomainGeneralInfo']['HitsCount'] !=None:
                    i['$KLHits'] = json_response['DomainGeneralInfo']['HitsCount']
            except Exception:
                pass
            try:
                if json_response['DomainGeneralInfo']['Ipv4Count'] != None and json_response['DomainGeneralInfo']['Ipv4Count']!=[]:
                    i['$KLIPv4Count'] = json_response['DomainGeneralInfo']['Ipv4Count']
            except Exception:
                pass
            try:
                if json_response['DomainGeneralInfo']['UrlsCount'] !=None and json_response['DomainGeneralInfo']['UrlsCount'] !=[]:
                    i['$KLURLCount'] = json_response['DomainGeneralInfo']['UrlsCount']
            except Exception:
                pass
            try:
                i['$KLHasAdvancedPersistThreat']= json_response['DomainGeneralInfo']['HasApt']
            except Exception:
                pass
            try:
                fred=[]
                fgrey=[]
                fgreen=[]
                fyellow = []
                for zn in json_response['DomainDnsResolutions']:
                    if zn['Zone'] =='Red':
                        fred.append(zn['Ip'])
                    elif zn['Zone'] =='Grey':
                        fgrey.append(zn['Ip'])
                    elif zn['Zone'] =='Green':
                        fgreen.append(zn['Ip'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Ip'])
                if len(fred)>0:
                    i['$KLRedDomainDnsResolutionsIP'] =fred
                if len(fgreen)>0:
                    i['$KLGreenDomainDnsResolutionsIP'] =fgreen
                if len(fgrey)>0:
                    i['$KLGreyDomainDnsResolutionsIP'] =fgrey
                if len(fyellow)>0:
                    i['$KLYellowDomainDnsResolutionsIP'] =fyellow
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['UrlReferrals']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedURLReferrals'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenURLReferrals'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyURLReferrals'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowURLReferrals'] = list(set(fyellow))
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['UrlReferredTo']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedURLReferredTo'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenURLReferredTo'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyURLReferredTo'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowURLReferredTo'] = list(set(fyellow))
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['Created'] != None and json_response['DomainWhoIsInfo']['Created']!=[]:
                    i['$KLCreated']=json_response['DomainWhoIsInfo']['Created']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['DomainName'] !=None and json_response['DomainWhoIsInfo']['DomainName'] !=[]:
                    i['$KLDomainName']=json_response['DomainWhoIsInfo']['DomainName']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['DomainStatus'] !=None and json_response['DomainWhoIsInfo']['DomainStatus']!=[]:
                    i['$KLDomainStatus']=json_response['DomainWhoIsInfo']['DomainStatus']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['Expires']!=None and json_response['DomainWhoIsInfo']['Expires']!=[]:
                    i['$KLExpires']= json_response['DomainWhoIsInfo']['Expires']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['NameServers'] !=None and json_response['DomainWhoIsInfo']['NameServers']!=[]:
                    i['$KLNameServers'] = json_response['DomainWhoIsInfo']['NameServers']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['Registrar']['Email'] !=None and json_response['DomainWhoIsInfo']['Registrar']['Email']!=[]:
                    i['$KLRegistrarEmail'] = json_response['DomainWhoIsInfo']['Registrar']['Email']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['Registrar']['IanaId'] !=None and json_response['DomainWhoIsInfo']['Registrar']['IanaId']!=[]:
                    i['$KLRegistrarIanaId'] = json_response['DomainWhoIsInfo']['Registrar']['IanaId']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['Registrar']['Info'] !=None and json_response['DomainWhoIsInfo']['Registrar']['Info']!=[]:
                    i['$KLRegistrarInfo']= json_response['DomainWhoIsInfo']['Registrar']['Info']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['RegistrationOrganization'] !=None and json_response['DomainWhoIsInfo']['RegistrationOrganization']!=[]:
                    i['$KLRegistrationOrganization']= json_response['DomainWhoIsInfo']['RegistrationOrganization']
            except Exception:
                pass
            try:
                if json_response['DomainWhoIsInfo']['Updated'] !=[] and json_response['DomainWhoIsInfo']['Updated']!=None:
                    i['$KLUpdated']=json_response['DomainWhoIsInfo']['Updated']
            except Exception:
                pass
            try:
                role=[]
                for rl in json_response['DomainWhoIsInfo']['Contacts']:
                    role.append(rl['ContactType'])
                for r in json_response['DomainWhoIsInfo']['Contacts']:
                    if r['ContactType'] in role:
                        if r['Address']!=None:
                            i['$KL' + str(r['ContactType']).title()+'Address']=r['Address']
                        if r['City'] != None:
                            i['$KL'+ str(r['ContactType']).title()+'City']=r['City']
                        if r['CountryCode'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'CountryCode'] = r['CountryCode']
                        if r['Email'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Email'] = r['Email']
                        if r['Fax'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Fax'] = r['Fax']
                        if r['Name'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Name'] = r['Name']
                        if r['Organization'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Organization'] = r['Organization']
                        if r['Phone'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Phone'] = r['Phone']
                        if r['PostalCode'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'PostalCode'] = r['PostalCode']
                        if r['State'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'State']=r['State']
            except Exception:
                pass
            try:
                i['$KLZone'] = json_response['Zone']
            except Exception:
                pass
            try:
                if json_response['Subdomains']['FilesCount']!=None and json_response['Subdomains']['FilesCount']!=[]:
                    i['$KLSubdomainsFilesCount']=json_response['Subdomains']['FilesCount']
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['Subdomains']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Subdomain'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Subdomain'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Subdomain'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Subdomain'])
                if len(fred) > 0:
                    i['$KLRedSubdomains'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenSubdomains'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreySubdomains'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowSubdomains'] = list(set(fyellow))
            except Exception:
                pass
    return inward_array


def get_domain_report_generalinfo(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/domain/'+str(i[var_array[0]])+'?sections=DomainGeneralInfo'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                i['$KLCategories'] = json_response['DomainGeneralInfo']['Categories']
            except Exception:
                pass
            try:
                i['$KLDomain'] = json_response['DomainGeneralInfo']['Domain']
            except Exception:
                pass
            try:
                i['$KLFilesCount'] = json_response['DomainGeneralInfo']['FilesCount']
            except Exception:
                pass
            try:
                i['$KLHits'] = json_response['DomainGeneralInfo']['HitsCount']
            except Exception:
                pass
            try:
                i['$KLIPv4Count'] = json_response['DomainGeneralInfo']['Ipv4Count']
            except Exception:
                pass
            try:
                i['$KLURLsCount'] = json_response['DomainGeneralInfo']['UrlsCount']
            except Exception:
                pass
            try:
                i['$KLHasAdvancedPersistThreat']= json_response['DomainGeneralInfo']['HasApt']
            except Exception:
                pass
    return inward_array


def get_domain_report_dnsresolution(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/domain/'+str(i[var_array[0]])+'?sections=DomainDnsResolutions'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                fred=[]
                fgrey=[]
                fgreen=[]
                fyellow = []
                for zn in json_response['DomainDnsResolutions']:
                    if zn['Zone'] =='Red':
                        fred.append(zn['Ip'])
                    elif zn['Zone'] =='Grey':
                        fgrey.append(zn['Ip'])
                    elif zn['Zone'] =='Green':
                        fgreen.append(zn['Ip'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Ip'])
                if len(fred)>0:
                    i['$KLMalwareStatusIP'] =fred
                if len(fgreen)>0:
                    i['$KLGoodStatusIP'] =fgreen
                if len(fgrey)>0:
                    i['$KLNotCategorisedIStatusP'] =fgrey
                if len(fyellow)>0:
                    i['$KLAdwareStatusIP'] =fyellow
            except Exception:
                pass
    return inward_array


def get_domain_report_url(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/domain/'+str(i[var_array[0]])+'?sections=UrlReferrals,UrlReferredTo'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['UrlReferrals']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedURLReferrals'] = fred
                if len(fgreen) > 0:
                    i['$KLGreenURLReferrals'] = fgreen
                if len(fgrey) > 0:
                    i['$KLGreyURLReferrals'] = fgrey
                if len(fyellow) > 0:
                    i['$KLYellowURLReferrals'] = fyellow
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['UrlReferredTo']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedURLReferredTo'] = fred
                if len(fgreen) > 0:
                    i['$KLGreenURLReferredTo'] = fgreen
                if len(fgrey) > 0:
                    i['$KLGreyURLReferredTo'] = fgrey
                if len(fyellow) > 0:
                    i['$KLYellowURLReferredTo'] = fyellow
            except Exception:
                pass
    return inward_array


def get_domain_report_whois(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/domain/'+str(i[var_array[0]])+'?sections=DomainWhoIsInfo'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                i['$KLCreated']=json_response['DomainWhoIsInfo']['Created']
            except Exception:
                pass
            try:
                i['$KLDomainName']=json_response['DomainWhoIsInfo']['DomainName']
            except Exception:
                pass
            try:
                i['$KLDomainStatus']=json_response['DomainWhoIsInfo']['DomainStatus']
            except Exception:
                pass
            try:
                i['$KLExpires']= json_response['DomainWhoIsInfo']['Expires']
            except Exception:
                pass
            try:
                i['$KLNameServers'] = json_response['DomainWhoIsInfo']['NameServers']
            except Exception:
                pass
            try:
                i['$KLRegistrarEmail'] = json_response['DomainWhoIsInfo']['Registrar']['Email']
            except Exception:
                pass
            try:
                i['$KLRegistrarIanaId'] = json_response['DomainWhoIsInfo']['Registrar']['IanaId']
            except Exception:
                pass
            try:
                i['$KlRegistrarInfo']= json_response['DomainWhoIsInfo']['Registrar']['Info']
            except Exception:
                pass
            try:
                i['$KLRegistrationOrganization']= json_response['DomainWhoIsInfo']['RegistrationOrganization']
            except Exception:
                pass
            try:
                i['$KLUpdated']=json_response['DomainWhoIsInfo']['Updated']
            except Exception:
                pass
            try:
                role=[]
                for rl in json_response['DomainWhoIsInfo']['Contacts']:
                    role.append(rl['ContactType'])
                for r in json_response['DomainWhoIsInfo']['Contacts']:
                    if r['ContactType'] in role:
                        i['$KL' + r['ContactType']+'Address']=r['Address']
                        i['$KL'+ r['ContactType']+'City']=r['City']
                        i['$KL' + r['ContactType'] + 'CountryCode'] = r['CountryCode']
                        i['$KL' + r['ContactType'] + 'Email'] = r['Email']
                        i['$KL' + r['ContactType'] + 'Fax'] = r['Fax']
                        i['$KL' + r['ContactType'] + 'Name'] = r['Name']
                        i['$KL' + r['ContactType'] + 'Organization'] = r['Organization']
                        i['$KL' + r['ContactType'] + 'Phone'] = r['Phone']
                        i['$KL' + r['ContactType'] + 'PostalCode'] = r['PostalCode']
                        i['$KL' + r['ContactType'] + 'State']=r['State']
            except Exception:
                pass
    return inward_array


def get_domain_report_file(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/domain/'+str(i[var_array[0]])+'?sections=FilesAccessed,FilesDownloaded'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['FilesAccessed']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Md5'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Md5'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Md5'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Md5'])
                if len(fred) > 0:
                    i['$KLRedFileAccessedMd5'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenFileAccessedMd5'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyFileAccessedMd5'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowFileAccesedMd5'] = list(set(fyellow))
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['FilesDownloaded']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Md5'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Md5'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Md5'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Md5'])
                if len(fred) > 0:
                    i['$KLRedFileDownloadedMd5'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenFileDownloadedMd5'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyFileDownloadedMd5'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowFileDownloadedMd5'] = list(set(fyellow))
            except Exception:
                pass
    return inward_array


def get_url_report_file(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/url/'+str(i[var_array[0]])+'?sections=FilesAccessed,FilesDownloaded'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['FilesAccessed']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Md5'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Md5'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Md5'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Md5'])
                if len(fred) > 0:
                    i['$KLRedFileAccessedMd5'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenFileAccessedMd5'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyFileAccessedMd5'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowFileAccessedMd5'] = list(set(fyellow))
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['FilesDownloaded']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Md5'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Md5'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Md5'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Md5'])
                if len(fred) > 0:
                    i['$KLRedFileDownloadedMd5'] = fred
                if len(fgreen) > 0:
                    i['$KLGreenFileDownloadedMd5'] = fgreen
                if len(fgrey) > 0:
                    i['$KLGreyFileDownloadedMd5'] = fgrey
                if len(fyellow) > 0:
                    i['$KLYellowFileDownloadedMd5'] = fyellow
            except Exception:
                pass
    return inward_array


def get_url_report(inward_array,var_array):
    for i in inward_array:
        if var_array[0] in i:
            params = 'https://tip.kaspersky.com/api/url/'+str(i[var_array[0]])+'?sections=Zone,UrlReferredTo,UrlReferrals,UrlGeneralInfo,UrlDomainWhoIs,DomainDnsResolutions'
            try:
                res = requests.get(params,cert=ks_cert_path,headers=headers)
                json_response = res.json()
            except Exception, e:
               logging.warning('Api Request Error %s' %e)
            try:
                i['$KLZone'] = json_response['Zone']
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['UrlReferredTo']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedUrlReferredTo'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenUrlReferredTo'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyUrlReferredTo'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowUrlReferredTo'] =list(set(fyellow))
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['UrlReferrals']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Url'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Url'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Url'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Url'])
                if len(fred) > 0:
                    i['$KLRedURLReferrals'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenURLReferrals'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyURLReferrals'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowURLReferrals'] = list(set(fyellow))
            except Exception:
                pass
            try:
                if json_response['UrlGeneralInfo']['Categories']!=[]:
                    i['$KLURLCategories']=json_response['UrlGeneralInfo']['Categories']
            except Exception:
                pass
            try:
                if json_response['UrlGeneralInfo']['FilesCount'] !=None and json_response['UrlGeneralInfo']['FilesCount'] !=[] :
                    i['$KLFilesCount']=json_response['UrlGeneralInfo']['FilesCount']
            except Exception:
                pass
            try:
                if json_response['UrlGeneralInfo']['Ipv4Count'] !=None and json_response['UrlGeneralInfo']['Ipv4Count']!=[]:
                    i['$KLIPv4Count']=json_response['UrlGeneralInfo']['Ipv4Count']
            except Exception:
                pass
            try:
                i['$KLHasAdvancedPersistThreat']=json_response['UrlGeneralInfo']['HasApt']
            except Exception:
                pass
            try:
                i['$KLURL'] = json_response['UrlGeneralInfo']['Url']
            except Exception:
                pass
            try:
                if json_response['UrlGeneralInfo']['Host'] != None and json_response['UrlGeneralInfo']['Host']!=[]:
                    i['$KLHost']=json_response['UrlGeneralInfo']['Host']
            except Exception:
                pass
            try:
                fred = []
                fgrey = []
                fgreen = []
                fyellow = []
                for zn in json_response['DomainDnsResolutions']:
                    if zn['Zone'] == 'Red':
                        fred.append(zn['Ip'])
                    elif zn['Zone'] == 'Grey':
                        fgrey.append(zn['Ip'])
                    elif zn['Zone'] == 'Green':
                        fgreen.append(zn['Ip'])
                    elif zn['Zone'] == 'Yellow':
                        fyellow.append(zn['Ip'])
                if len(fred) > 0:
                    i['$KLRedIPResoutions'] = list(set(fred))
                if len(fgreen) > 0:
                    i['$KLGreenIPResoutions'] = list(set(fgreen))
                if len(fgrey) > 0:
                    i['$KLGreyIPResoutions'] = list(set(fgrey))
                if len(fyellow) > 0:
                    i['$KLYellowIPResoutions'] = list(set(fyellow))
            except Exception:
                pass
            try:
                role=[]
                for rl in json_response['UrlDomainWhoIs']['Contacts']:
                    role.append(rl['ContactType'])
                for r in json_response['UrlDomainWhoIs']['Contacts']:
                    if r['ContactType'] in role:
                        if r['Address']!=None:
                            i['$KL' + str(r['ContactType']).title()+'Address']=r['Address']
                        if r['City'] != None:
                            i['$KL'+ str(r['ContactType']).title()+'City']=r['City']
                        if r['CountryCode'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'CountryCode'] = r['CountryCode']
                        if r['Email'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Email'] = r['Email']
                        if r['Fax'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Fax'] = r['Fax']
                        if r['Name'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Name'] = r['Name']
                        if r['Organization'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Organization'] = r['Organization']
                        if r['Phone'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'Phone'] = r['Phone']
                        if r['PostalCode'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'PostalCode'] = r['PostalCode']
                        if r['State'] != None:
                            i['$KL' + str(r['ContactType']).title() + 'State']=r['State']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['Created'] != None and json_response['UrlDomainWhoIs']['Created']!=[]:
                    i['$KLCreated'] = json_response['UrlDomainWhoIs']['Created']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['DomainName'] !=None and json_response['UrlDomainWhoIs']['DomainName']!=[]:
                    i['$KLDomainName']= json_response['UrlDomainWhoIs']['DomainName']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['DomainStatus'] !=None and json_response['UrlDomainWhoIs']['DomainStatus']!=[]:
                    i['$KLDomainStatus'] = json_response['UrlDomainWhoIs']['DomainStatus']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['Expires'] !=None and json_response['UrlDomainWhoIs']['Expires']!=[]:
                    i['$KLExpires'] = json_response['UrlDomainWhoIs']['Expires']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['NameServers'] !=None and json_response['UrlDomainWhoIs']['NameServers'] !=[]:
                    i['$KLNameServers'] = json_response['UrlDomainWhoIs']['NameServers']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['RegistrationOrganization'] !=[] and json_response['UrlDomainWhoIs']['RegistrationOrganization']!= None:
                    i['$KLRegistrationOrganization'] = json_response['UrlDomainWhoIs']['RegistrationOrganization']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['Updated'] != None and json_response['UrlDomainWhoIs']['Updated'] !=[]:
                    i['$KLUpdated'] = json_response['UrlDomainWhoIs']['Updated']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['Registrar']['Email'] != None and json_response['UrlDomainWhoIs']['Registrar']['Email'] !=[]:
                    i['$KLRegistrarEmail'] = json_response['UrlDomainWhoIs']['Registrar']['Email']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['Registrar']['IanaId'] != None and json_response['UrlDomainWhoIs']['Registrar']['IanaId'] != []:
                    i['$KLRegistrarIanaId'] = json_response['UrlDomainWhoIs']['Registrar']['IanaId']
            except Exception:
                pass
            try:
                if json_response['UrlDomainWhoIs']['Registrar']['Info'] != None and json_response['UrlDomainWhoIs']['Registrar']['Info'] !=[]:
                    i['$KLRegistrarInfo'] = json_response['UrlDomainWhoIs']['Registrar']['Info']
            except Exception:
                pass
    return inward_array


