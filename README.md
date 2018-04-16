## Kaspersky Threat Intelligence Portal   
  https://tip.kaspersky.com/

### Overview
Kaspersky Threat Intelligence Portal provides reliable, immediate intelligence about cyber-threats, legitimate objects, their interconnections and indicators, enriched with actionable context to inform your business or clients about the associated risks and implications. Now you can mitigate and respond to threats more effectively, defending your system against attacks even before they are launched.

Kaspersky Threat Intelligence Portal delivers all the knowledge acquired by Kaspersky Lab about cyber-threats and their relationships, brought together into a single, powerful web service. The goal is to provide your security teams with as much data as possible in order to prevent cyber-attacks that can impact your organization. The platform retrieves the latest detailed threat intelligence about URLs, domains, IP addresses, file hashes, statistical / behavioral data, WHOIS / DNS data, and so on. The result is global visibility of new and emerging threats, helping you secure your organization and boosting incident response.

Threat intelligence is aggregated from fused, heterogeneous, and highly reliable sources. Then, in real time, all the aggregated data is carefully inspected and refined using multiple preprocessing techniques, such as statistical criteria, Kaspersky Lab expert systems, validation by analysts, and white-listing verification.

#### How it works
Indicators of compromise can be looked up through a web-based interface or Kaspersky Threat Intelligence Portal API. Kaspersky Threat Intelligence Portal enables you to request threat intelligence about the following objects
- MD5 hashes
- IP addresses
- Domains
- URLs

Kaspersky Threat Intelligence Portal displays whether an object is in Good, Bad, or Not categorized zones, while providing a rich set of contextual data to answer the who, what, where, and when questions that help you respond to or investigate threats more effectively.

#### Key features
The following are the key features of Kaspersky Threat Intelligence Portal  

- APT Intelligence reports and Financial Threat Intelligence reports
Increase your awareness and knowledge of high profile cyber-espionage campaigns with wide-ranging and practical advanced persistent threat (APT) reporting from Kaspersky Lab. Download reports in any available format.

- Data feeds
Security Threat Intelligence Services from Kaspersky Lab gives you access to the intelligence you need to mitigate cyber threats, provided by our world-class team of researchers and analysts.

- Trusted threat intelligence
The key benefit of threat intelligence is the reliability of data enriched with actionable context.

- Comprehensive and real-time coverage
Threat intelligence is automatically generated in real time, based on findings across the globe, providing high coverage and accuracy.

- Rich data
Threat intelligence delivered by Kaspersky Threat Intelligence Portal includes a vast amount of different data types such as hashes, URLs, IP addresses, WHOIS, GeoIP, pDNS, file attributes, statistical and behavioral data, download chains, time stamps, and much more. Empowered with this data, you have access to a diverse landscape of security threats.

- Continuous availability
Threat intelligence delivered by Kaspersky Threat Intelligence Portal is generated and monitored by a highly fault-tolerant infrastructure, ensuring continuous availability and consistent performance.

- Continuous review by security experts
Hundreds of experts, including security analysts from across the globe, world-famous security experts from Global Research & Analysis Team (GReAT), and leading-edge R&D teams, contribute to generating valuable and real-life threat intelligence.

- Easy-to-use API
Use the service in manual mode through a web portal or get access by means of a simple Kaspersky Threat Intelligence Portal API.

- SaaS solution
With software as a service (SaaS), there is no need to integrate additional systems or services into your company’s infrastructure. Start using the service immediately.

#### Lookups integrated with Kaspersky Threat Intelligence Portal API

#### Retrieve IP address investigation report

The IP address for which you want to retrieve the report
- input : a valid IPv4 address.

```
_fetch $SrcIP from threatsample limit 1
>>_lookup kaspersky get_ip_report $SrcIP
```
###### Sample Output     
[IP-REPORT](https://www.youtube.com/watch?v=n_h63oJQHCY)  
The Lookup call returns output in the following structure for available data  

 | Fields        | Description  |
|:------------- |:-------------|
| $KLIPDNSResolustionsCategories      | Category of the requested IP address |
| $KLIPDNSResolustionsDomains | Domain that resolves to the requested IP address |
| $KLCategory | Category of the requested IP address |
| $KLFirstSeen | Date and time when the requested IP address appeared in Kaspersky Lab expert systems statistics for the first time. |
| $KLHits | Hits number (popularity) of the requested IP address |
| $KLThreatScore | Probability of the requested IP address to appear dangerous (0 to 100)  |
| $KLHasAdvancedPersistThreat  | Shows whether the requested IP address is related to an advanced persistent threat (APT) attack |
| $KLCreated | Created Date of network that requested IP address belongs to |
| $KLChanged | Changed Date of network that requested IP address belongs to |
| $KLIPRange | Range of network that requested IP address belongs to |
| $KLNetname | Name of network that requested IP address belongs to |
| $KLNetDescription | Description of network that requested IP address belongs to |
| $KLZone | Color of the zone that a domain (resolved to the requested IP address) belongs to (red, gray, green) |
| $KLASN | Autonomous system number |
| $KLASDescription | Autonomous system description  |

IPWHOIS Information of the queried IP address contains contact information which vary depending on the roles present in the data 
For instance for role as Owner the data for available fields would be

 | Fields        | Description  |
|:------------- |:-------------|
| $KLOwnerAddress      | Address of owner present in the IPWHOIS data |
| $KLOwnerName | Name of the owner present in the IPWHOIS data  |
| $KLOwnerFax | Fax of the owner present in the IPWHOIS data |
| $KLOwnerEmail | Email of the owner present in the IPWHOIS data |
| $KLOwnerOrganizationId | Organization Id of the owner present in the IPWHOIS data  |
| $KLOwnerPhone | Phone details  of the owner present in the IPWHOIS data |


#### Retrieve URLs hosted and files downloaded by IP
The IP address for which you want to retrieve the report
- input : a valid IPv4 address.
```
_fetch $SrcIP from threatsample limit 1
>>_lookup kaspersky get_ip_filehostdownload_report $SrcIP
```
###### Sample Output     
[IP-File-URL-Report](https://www.youtube.com/watch?v=ncV9Jg-dEaM)  

Note

| Zone        | Description  |
|:------------- |:-------------|
| Red | The investigated object can be classified as malicious |
| Grey |  No data is available for the investigated object |
| Green | The investigated object cannot be classified as malicious|
| Yellow | The investigated object has the Adware and other status (Adware, Pornware, and other programs) |


The Lookup call returns output in the following structure for available data  

| Fields        | Description  |
|:------------- |:-------------|
| $KLHostedURL      | List of detected URLs of the domain that resolves to the requested IP address |
| $KLRedMd5 | List of MD5 hash function of the downloaded file from the queried IP address belonging to Red Zone |
| $KLGreenMd5 | List of MD5 hash function of the downloaded file from the queried IP address belonging to Green Zone |
| $KLGreyMd5 | List of MD5 hash function of the downloaded file from the queried IP address belonging to Grey Zone |
| $KLYellowMd5 | List of MD5 hash function of the downloaded file from the queried IP address belonging to Yellow Zone |



#### Retrieve URL investigation report
The URL for which you want to retrieve the report
- input : The URL to be queried

```
_fetch $Url from threatsample limit 1
>>_lookup kaspersky get_url_report $Url
```

###### Sample Output  
[URL-Report](https://www.youtube.com/watch?v=kiWyKNyY9UM)  

Note

| Zone        | Description  |
|:------------- |:-------------|
| Red | The investigated object can be classified as malicious |
| Grey |  No data is available for the investigated object |
| Green | The investigated object cannot be classified as malicious|
| Yellow | The investigated object has the Adware and other status (Adware, Pornware, and other programs) |


The Lookup call returns output in the following structure for available data  

| Fields        | Description  |
|:------------- |:-------------|
| $KLZone | Color of the zone that queried URL belongs to (red, gray, green) |
| $KLRedUrlReferredTo | URL accessed by the queried URL which belong to Red Zone |
| $KLGreenUrlReferredTo | URL accessed by the queried URL which belong to Green Zone |
| $KLGreyUrlReferredTo | URL accessed by the queried URL which belong to Grey Zone |
| $KLYellowUrlReferredTo | URL accessed by the queried URL which belong to Yellow Zone |
| $KLRedUrlReferrals | URL that refers to the queried URL which belong to Red Zone |
| $KLGreenUrlReferrals | URL that refers to the queried URL which belong to Green Zone |
| $KLGreyUrlReferrals | URL that refers to the queried URL which belong to Grey Zone |
| $KLYellowUrlReferrals | URL that refers to the queried URL which belong to Yellow Zone |
| $KLURLCategories | Category of the requested URL |
| $KLFilesCount | Number of files for the requested URL |
| $KLIPv4Count | Number of IP addresses (IPv4) for the requested URL |
| $KLHasAdvancedPersistThreat | Shows whether the requested URL is related to an advanced persistent threat (APT) attack |
| $KLURL | The requested URL |
| $KLHost | Name of the upper-level domain of the requested URL |
| $KLRedIPResoutions | IP address obtained from DomainDnsResoutions which belong to Red Zone |
| $KLGreenIPResoutions | IP address obtained from DomainDnsResoutions which belong to Green Zone |
| $KLGreyIPResoutions | IP address obtained from DomainDnsResoutions which belong to Grey Zone |
| $KLYellowIPResoutions | IP address obtained from DomainDnsResoutions which belong to Yellow Zone |
| $KLCreated | Date when the domain for the requested URL was registered |
| $KLDomainName | Name of the domain of the requested URL |
| $KLDomainStatus | Statuses of the domain |
| $KLExpires | Expiration date of the prepaid domain registration term. |
| $KLNameServers | Name servers of the domain for the requested URL |
| $KLRegistrationOrganization | Name of the registration organization |
| $KLUpdated | Date when registration information about the domain for the requested URL was last updated |
| $KLRegistrarEmail | Email of the registrar of the domain |
| $KLRegistrarIanaId | IANA ID of the registrar of the domain |
| $KLRegistrarInfo | Name of the registrar of the domain |

UrlDomainWhoIs Information of the queried URL contains contact information which vary depending on the contact type present in the data 
For instance for contact type as Technical the data for available fields would be

 | Fields        | Description  |
|:------------- |:-------------|
| $KLTechnicalAddress | Address of Technical contact present in the UrlDomainWhoIs data |
| $KLTechnicalCity | City of the Technical contact present in the UrlDomainWhoIs data  |
| $KLTechnicalCountryCode | Country Code of the Technical contact present in the UrlDomainWhoIs data |
| $KLTechnicalEmail  | Email of the Technical contact present in the UrlDomainWhoIs data |
| $KLTechnicalFax  | Fax of the Technical contact present in the UrlDomainWhoIs data  |
| $KLTechnicalName  | Name of the Technical contact present in the UrlDomainWhoIs data |
| $KLTechnicalOrganization  | Organization  of the Technical contact  present in the UrlDomainWhoIs data |
| $KLTechnicalPhone  | Phone details  of the Technical contact present in the UrlDomainWhoIs data |
| $KLTechnicalPostalCode  | Postal Code of the Technical contact present in the UrlDomainWhoIs data |
| $KLTechnicalState  | State of the Technical contact present in the UrlDomainWhoIs data |


#### Retrieve files accessed by URL and files downloaded from URL
The URL for which you want to retrieve the report
- input : The URL to be queried
```
_fetch $Url from threatsample limit 1
>>_lookup kaspersky get_url_report_file $Url
```

###### Sample Output  
[URL-File-Report](https://www.youtube.com/watch?v=YqR3KFJm6Mg)  

Note

| Zone        | Description  |
|:------------- |:-------------|
| Red | The investigated object can be classified as malicious |
| Grey |  No data is available for the investigated object |
| Green | The investigated object cannot be classified as malicious|
| Yellow | The investigated object has the Adware and other status (Adware, Pornware, and other programs) |


The Lookup call returns output in the following structure for available data  

| Fields        | Description  |
|:------------- |:-------------|
| $KLRedFileAccessedMd5 | List of MD5 hashes of files that accessed the requested URL belonging to Red Zone |
| $KLGreenFileAccessedMd5 | List of MD5 hashes of files that accessed the requested URL belonging to Green Zone |
| $KLGreyFileAccessedMd5 | List of MD5 hashes of files that accessed the requested URL belonging to Grey Zone |
| $KLYellowFileAccessedMd5 | List of MD5 hashes of files that accessed the requested URL belonging to Yellow Zone |
| $KLRedFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested URL belonging to Red Zone |
| $KLGreenFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested URL belonging to Green Zone |
| $KLGreyFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested URL belonging to Grey Zone |
| $KLYellowFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested URL belonging to Yellow Zone |


#### Retrieve Domain investigation report
The Domain for which you want to retrieve the report
- input : The Domain to be queried

```
_fetch $Domain from threatsample limit 1
>>_lookup kaspersky get_domain_report $Domain
```
###### Sample Output  
[Domain-Report](https://www.youtube.com/watch?v=JiX2PUABfeg&t=42s)  

Note

| Zone        | Description  |
|:------------- |:-------------|
| Red | The investigated object can be classified as malicious |
| Grey |  No data is available for the investigated object |
| Green | The investigated object cannot be classified as malicious|
| Yellow | The investigated object has the Adware and other status (Adware, Pornware, and other programs) |


The Lookup call returns output in the following structure for available data  

| Fields        | Description  |
|:------------- |:-------------|
| $KLCategories | Category of the requested Domain |
| $KLDomain| Name of the requested Domain |
| $KLFilesCount | Number of files malicious/all files |
| $KLHits | Number of IP addresses related to the domain |
| $KLIPv4Count | Number of IP addresses (IPv4) for the requested domain |
| $KLURLCount | Number of known malicious/all URLs |
| $KLHasAdvancedPersistThreat | Shows whether the requested domain is related to an advanced persistent threat (APT) attack.|
| $KLRedDomainDnsResolutionsIP | IP address obtained from DomainDnsResoutions which belong to Red Zone |
| $KLGreenDomainDnsResolutionsIP | IP address obtained from DomainDnsResoutions which belong to Green Zone |
| $KLGreyDomainDnsResolutionsIP | IP address obtained from DomainDnsResoutions which belong to Grey Zone |
| $KLYellowDomainDnsResolutionsIP | IP address obtained from DomainDnsResoutions which belong to Yellow Zone |
| $KLRedURLReferrals | URL that refers to the queried domain which belong to Red Zone |
| $KLGreenURLReferrals | URL that refers to the queried domain which belong to Green Zone |
| $KLGreyURLReferrals | URL that refers to the queried domain which belong to Grey Zone |
| $KLYellowURLReferrals | URL that refers to the queried domain which belong to Yellow Zone | 
| $KLRedURLReferredTo | URL refered by the queried domain which belong to Red Zone |
| $KLGreenURLReferredTo | URL refered by the queried domain which belong to Green Zone |
| $KLGreyURLReferredTo | URL refered by the queried domain which belong to Grey Zone |
| $KLYellowURLReferredTo | URL refered by the queried domain which belong to Yellow Zone |
| $KLCreated | Date when the requested domain was registered |
| $KLDomainName | Name of the requested domain |
| $KLDomainStatus | Statuses of the domain |
| $KLExpires | Expiration date of the prepaid domain registration term |
| $KLNameServers | Name servers of the requested domain |
| $KLRegistrarEmail | Email of the registrar of the domain |
| $KLRegistrarIanaId | IANA ID of the registrar of the domain |
| $KLRegistrarInfo | Name of the registrar of the domain |
| $KLRegistrationOrganization | Name of the registration organization |
| $KLUpdated | Date when registration information about the requested domain was last updated |
| $KLZone | Color of the zone that queried domain belongs to (red,gray, green) |
| $KLSubdomainsFilesCount | Count of number of sub domains  |
| $KLRedSubdomains | List of sub-domains belonging to Red Zone |
| $KLGreenSubdomains | List of sub-domains belonging to Green Zone |
| $KLGreySubdomains | List of sub-domains belonging to Grey Zone |
| $KLYellowSubdomains | List of sub-domains belonging to Yellow Zone |


DomainWhoIsInfo Information of the queried domain contains contact information which vary depending on the contact present in the data 
For instance for contact as Registrant the data for available fields would be

 | Fields        | Description  |
|:------------- |:-------------|
| $KLRegistrantAddress | Address of Registrant present in the DomainWhoIsInfo data |
| $KLRegistrantCity | City of the Registrant present in the DomainWhoIsInfo data  |
| $KLRegistrantCountryCode | Country Code of the Registrant present in the DomainWhoIsInfo data |
| $KLRegistrantEmail  | Email of the Registrant present in the DomainWhoIsInfo data |
| $KLRegistrantFax  | Fax of the Registrant present in the DomainWhoIsInfo data  |
| $KLRegistrantName  | Name of the Registrant present in the DomainWhoIsInfo data |
| $KLRegistrantOrganization  | Organization  of the Registrant  present in the DomainWhoIsInfo data |
| $KLRegistrantPhone  | Phone details  of the Registrant present in the DomainWhoIsInfo data |
| $KLRegistrantPostalCode  | Postal Code of the Registrant present in the DomainWhoIsInfo data |
| $KLRegistrantState  | State of the Registrant present in the DomainWhoIsInfo data |


#### Retrieve files accessed by domain and files downloaded from domain
The domain for which you want to retrieve the report
- input : The domain to be queried
```
_fetch $Domain from threatsample limit 1
>>_lookup kaspersky get_domain_report_file $Domain
```
###### Sample Output   
[Domain-Report-Files](https://www.youtube.com/watch?v=YqR3KFJm6Mg)  

Note

| Zone        | Description  |
|:------------- |:-------------|
| Red | The investigated object can be classified as malicious |
| Grey |  No data is available for the investigated object |
| Green | The investigated object cannot be classified as malicious|
| Yellow | The investigated object has the Adware and other status (Adware, Pornware, and other programs) |


The Lookup call returns output in the following structure for available data  

| Fields        | Description  |
|:------------- |:-------------|
| $KLRedFileAccessedMd5 | List of MD5 hashes of files that accessed the requested domain belonging to Red Zone |
| $KLGreenFileAccessedMd5 | List of MD5 hashes of files that accessed the requested domain belonging to Green Zone |
| $KLGreyFileAccessedMd5 | List of MD5 hashes of files that accessed the requested domain belonging to Grey Zone |
| $KLYellowFileAccessedMd5 | List of MD5 hashes of files that accessed the requested domain belonging to Yellow Zone |
| $KLRedFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested domain belonging to Red Zone |
| $KLGreenFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested domain belonging to Green Zone |
| $KLGreyFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested domain belonging to Grey Zone |
| $KLYellowFileDownloadedMd5 | List of MD5 hashes of files that were downloaded from the requested domain belonging to Yellow Zone |


#### Retrieve Hash investigation report
The hash for which you want to retrieve the report
- input : The Md5/SHA-1/SHA-256 to be queried

```
_fetch $Filehash from threatsample limit 1
>>_lookup kaspersky get_hash_report $Filehash
```
###### Sample Output    
[Hash-Report](https://www.youtube.com/watch?v=YRyvRcgrA2U)      

Note

| Zone        | Description  |
|:------------- |:-------------|
| Red | The investigated object can be classified as malicious |
| Grey |  No data is available for the investigated object |
| Green | The investigated object cannot be classified as malicious|
| Yellow | The investigated object has the Adware and other status (Adware, Pornware, and other programs) |


The Lookup call returns output in the following structure for available data  

| Fields        | Description  |
|:------------- |:-------------|
| $KLHits | Number of hits (popularity) of the requested hash detected by Kaspersky Lab expert systems |
| $KLFirstSeen | Date and time when the requested hash was detected by Kaspersky Lab expert systems for the first time |
| $KLLastSeen | Date and time when the requested hash was detected by Kaspersky Lab expert systems for the last time |
| $KLMd5 | MD5 hash function of the file requested by hash |
| $KLSha1 | SHA-1 hash function of the file requested by hash |
| $KLSha256 | SHA-256 hash function of the file requested by hash |
| $KLFormat | Format of the object that is being investigated by hash |
| $KLSize | Size of the object that is being investigated by hash (in bytes) |
| $KLSigner | Organization that signed the requested hash |
| $KLPacker | Packer name |
| $KLDetectionNames | Name of the detected object |
| $KLDescriptionURL | Permalink containing description of detected object|
| $KLFileNames | Name of the file identified by the requested hash |
| $KLZone | Color of the zone that queried hash belongs to (red,gray, green) |
| $KLRedFileAccessedURL | URLs accessed by the file identified by the requested hash belonging to Red Zone |
| $KLGreenFileAccessedURL | URLs accessed by the file identified by the requested hash belonging to Green Zone |
| $KLGreyFileAccessedURL | URLs accessed by the file identified by the requested hash belonging to Grey Zone |
| $KLYellowFileAccessedURL | URLs accessed by the file identified by the requested hash belonging to Yellow Zone |
| $KLRedFileAccessedDomain | Upper domain of the URL used to download the file identified by the requested hash belonging to Red Zone |
| $KLGreenFileAccessedDomain | Upper domain of the URL used to download the file identified by the requested hash belonging to Green Zone |
| $KLGreyFileAccessedDomain | Upper domain of the URL used to download the file identified by the requested hash belonging to Grey Zone |
| $KLYellowFileAccessedDomain | Upper domain of the URL used to download the file identified by the requested hash belonging to Yellow Zone |


### Using the Kaspersky Threat Intelligence Portal API and DNIF  
The Kaspersky Threat Intelligence Portal API is found on github at 

  https://github.com/dnif/lookup-kaspersky

#### Getting started with Kaspersky Threat Intelligence Portal API and DNIF

1. #####    Login to your Data Store, Correlator, and A10 containers.  
   ACCESS DNIF CONTAINER VIA SSH : [Click To Know How](https://dnif.it/docs/guides/tutorials/access-dnif-container-via-ssh.html)
2. #####    Move to the ‘/dnif/<Deployment-key/lookup_plugins’ folder path.
```
$cd /dnif/CnxxxxxxxxxxxxV8/lookup_plugins/
```
3. #####   Clone using the following command  
```  
git clone https://github.com/dnif/lookup-kaspersky.git kaspersky
```
4. #####   Kaspersky Threat Intelligence Portal API certificate in PEM format
  - You must convert the certificate received from your dedicated Kaspersky Lab Technical Account Manager to PEM format     before working with the Kaspersky Threat Intelligence Portal API 
  - For coverting refer to : [Click To Know How](https://tip.kaspersky.com/help/Doc_data/ConvertingCertToPEM.htm)
  - Save the .pem certificate in a safe path
  
5. #####   Edit dnifconfig.yml configuration file by moving to the ‘/dnif/<Deployment-key/lookup_plugins/kaspersky/’ folder path      
    
   Replace the <tag> fields with your Kaspersky Threat Intelligence Portal credentials
```
lookup_plugin:
    KASPERSKY_API_USERNAME: <Add_your_api_username_here>
    KASPERSKY_API_PASSWORD: <Add_your_api_path_here>
    KASPERSKY_API_CERT_PATH:  </path/to/your/.pem>

```
