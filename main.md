%%%
title = "Cross Device Flows: Security Best Current Practice"
abbrev = "CDFS"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-kasselman-cross-device-security-00"
stream = "IETF"
status = "standard"


[[author]]
initials="P."
surname="Kasselman"
fullname="Pieter Kasselman"
organization="Microsoft"
    [author.address]
    email = "pieter.kasselman@microsoft.com"
    
    
[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="yes.com"
    [author.address]
    email = "mail@danielfett.de"


[[author]]
initials="F."
surname="Skokan"
fullname="Filip Skokan"
organization="Okta"
    [author.address]
    email = "filip.skokan@okta.com"


%%%

.# Abstract 

This document describes the threats against cross-device flows 
along with near term mitigations, protocol selection guidance 
and the analytical tools needed to evaluate the effectiveness of 
these mitigations. It serves as a security guide to system designers, 
architects, product managers, security specialists, fraud analysts 
and engineers implementing cross-device flows.

{mainmatter}


# Introduction {#Introduction}
Cross-device flows enable a user initiate and authorization flow on 
one device (the initiating device) and then use a second, personally 
trusted device (authorization device), to authorize access to a resource 
(e.g. access to a service). 

In a typical example of a cross-device flow, the user takes an action on 
the initiating device by starting a purchase, adding a device to a network 
or connecting a service to the initiating device. This action results in a 
QR code or user code being displayed on the initiating device. The user 
then scans the QR code or enter the user code on the authenticating device
before completing the authorization on the authentication device. The 
session between the initiating device and the authorization device is 
linked through the QR code or user code.

In some variant of these flows, the user receives a push notification on 
their authenticating device that triggers the authorization flow, removing 
the need to scan a QR code or enter a user code manually. 

These flows are increasingly popular and typically involve using a mobile 
phone to scan a QR code or enter a user code displayed on an initiating 
device (e.g. Smart TV, Kiosk, PC etc).

The channel between the initiating device and the authorization device is 
unauthenticated and relies on the user's judgment to decide whether to trust 
a QR code, user code or the authorization request pushed to their authorization 
device. Several publications have emerged in the public domain, describing how 
the unauthenticated channel can be exploited using social engineering techniques 
borrowed from phishing. Unlike traditional phishing attacks, these attacks don’t 
harvest credentials. Instead, they skip the step of collecting credentials by 
persuading users into granting authorization using their authorization devices. 
Once the user grants authorization, the attacker has access to access to the users 
resources and in some cases are able to collect access and refresh tokens. Once in 
possession of the access and refresh tokens, the attacker may use these tokens to
execute lateral attacks and gain additional access, or monetize the tokens by 
selling them. These attacks are effective, even when multi-factor authentication 
is deployed, since the attacker's aim is not to capture and replay the credentials, 
but rather to persuade the user to grant authorization. 

In order to defend against these attacks, this document outlines three responses:

1. Deploy practical mitigations with protocols that are susceptible to unauthenticated 
channel exploits.
2. Select protocols that are not susceptible to unauthenticated channel exploits 
when possible.
3. Conduct formal analysis of cross-device flows to assess susceptibility to 
    these attacks and the effectiveness of the proposed mitigations.

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they
appear in all capitals, as shown here.

This specification uses the terms "access token", "refresh token",
"authorization server", "resource server", "authorization endpoint",
"authorization request", "authorization response", "token endpoint",
"grant type", "access token request", "access token response", and
"client" defined by The OAuth 2.0 Authorization Framework [@!RFC6749].

# Cross Device Flow
In a cross-device flow, a user starts a scenario on the initiating device 
(e.g. a PC) and then uses a authorization device (e.g. a smartphone) to 
authorize access to a resource (e.g. access to a streaming service). This 
has several benefits, including:

- **Authorization on devices with limited input capabilities:** End-users can 
authorize devices with limited input capabilities to access content (e.g. 
smart TVs, digital whiteboards, printers, etc).
- **Secure authentication on shared or public devices:** End-users can perform 
authentication and authorization using a personally trusted device, without 
risk of disclosing their credentials to a public or shared device. 
- **Ubiquitous multi-factor authentication:** Enables a user to use multi-factor 
authentication, independent of the device on which the service is being 
accessed (e.g. a kiosk, smart TV or shared PC).
- **Convenience of a single, portable, credential store:** Users can keep all 
their credentials in a mobile wallet or mobile phone that they already 
carry with them. 

Examples of cross-device flow scenarios include:

##Example 1: Authorize access to a video streaming service 
An end-user sets up a new smart TV and wants to connect it to their favorite streaming service. The TV displays a QR code that the user scans with their mobile phone. The user is redirected to the streaming service provider’s web page and asked to enter their credentials to authorize the smart TV to access the streaming service. The user enters their credentials and grant authorization, after which the streaming service is available on the smart TV.

##Example 2: Authorize access to productivity services
An employee wants to access their files on an interactive whiteboard in a conference room. The interactive whiteboard displays a URL and a code. The user enters the URL on their PC and is prompted for the code. Once they enter the code, the user is asked to authenticate and authorize the interactive whiteboard to access their files. The user enters their credentials and authorizes the transaction and the interactive whiteboard retrieves their files and allows the user to interact with the content.

##Example 3: Authorize use of a bike sharing scheme
An end-user wants to rent a bicycle from a bike sharing scheme. The bicycles are locked into bike racks on sidewalks throughout a city. To unlock and use a bike, the user scans a QR code on the bike using their mobile phone. Scanning the QR code redirects the user to the bike sharing scheme’s authorization page where the user authenticates and authorizes payment for renting the bike. Once authorized, the bike sharing service unlocks the bike, allowing the user to use it to cycle around the city.

##Example 4: Authorize a financial transaction
An end-user makes an online purchase. Before completing the purchase, they get a notification on their mobile phone, asking them to authorize the transaction. The user opens their app and authenticates to the service before authorizing the transaction.

##Example 5: Add a device to a network.
An employee is issued with a laptop computer that is already joined to a network. The employee wants to add their mobile phone to the network to allow them to access corporate data and services (e.g. files and e-mail). The PC displays a QR code, which the employee scans with their mobile phone. The mobile phone is joined to the network and the employee can start accessing corporate data and services on their mobile device.

##Example 6: Remote onboarding
A new employee is directed to an onboarding portal to provide additional information to confirm their identity on their first day with their new employer. Before activating the employee’s account, the onboarding portal requests that the employee present a government issued ID, proof of a background check and proof of their qualifications. The onboarding portal displays a QR code, which the user scans with their mobile phone. Scanning the QR code invokes the employee’s wallet on their mobile phone, and the employee is asked to present digital versions of mobile driving license, proof of a background check by an identity verifier and proof of their qualifications. The employee authorizes the release of the credentials and after completing the onboarding process, their account is activated. 


# Attacks and Mitigations

## Illicit Consent Grant Attack with Legitimate Device
### Attack 
The Device Authorization Grant allows a user to complete an authorization 
request on a different device from the one on which the request is 
initiatiated. This is achieved by presenting the user code and 
the verification URI obtained by the client from the authorization server 
to the user. The user access the verification URI and enters the user code
on their authroization device, thereby binding the authorisation request 
initiatied on the client to the authorization device. This reliance on the user 
to complete the protocol is exploited by a number of attacks ([ref1], [ref2], 
[ref3]).

In these attacks, an (A1) Web Attacker as described in [insert reference] that 
has access to a legitimate client device such as a smart TV, interactive 
whiteboard, or printer can inititate the Device Authorization Grant and obtain a 
verification uri (verification_uri) and user code (user_code). The attacker 
proceeds to trick the user into accesing the verification uri, enter the user code
and complete the authroization step, thereby obtaining illicit consent from the user
to access their resources. 

The attacker uses a number of common social engineering techniques similar to those 
employed in phishing attacks to convince the user to complete these steps. For 
example, the attacker may send an e-mail to an end user, informing them that they 
will be logged out of their service, unless they go to the verification URI, enter 
the user code and complete the authorization. The attacker may perform a targeted 
attack to obtain consent from a specific user, or may perfrom a "spray" attack, by 
sending such an e-mail to a broad audience in the hope that one of them will respond 
and authorise the request. Illicit consent grant attacks use similar techniques to 
phishing attacks but unlike phishing attacks does not collect the users credentials. 
Instead, it tricks the user into granting consent, thereby bypassing phishing 
countermeasures like multi-factor authentication. It can be executed without certain
aspects of phishing infrastructure, like web-sies that are setup to collct user 
credentials, which in turn makes these attacks harder to detect and requires different 
countermeasures.

### Mitigation


## Illicit Consent Grant Attack with Compromised Device

## Illicit Consent Grant Attack with Untrusted Device
A (A1) Web Attacker as described in [insert reference] has control of a 
legitimate client device. The attacker uses this device to initiate the 


### Social Engineering

### Token Exfiltration Attack



# IANA Considerations {#IANA}

[TBD]

{backmatter}

# Acknowledgements {#Acknowledgements}
      
We would like to thank [...] for their valuable input, feedback and general
support of this work.

# Document History

   [[ To be removed from the final specification ]]



   -00 

   *  the beginning of it all
   


<reference anchor="OpenID.Core" target="http://openid.net/specs/openid-connect-core-1_0.html">
  <front>
    <title>OpenID Connect Core 1.0</title>
    <author initials="N." surname="Sakimura" fullname="Nat Sakimura">
      <organization></organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization></organization>
    </author>
    <author initials="M.B." surname="Jones" fullname="Michael B. Jones">
      <organization></organization>
    </author>
    <author initials="B.d." surname="Medeiros" fullname="Breno de Medeiros">
      <organization></organization>
    </author>
    <author initials="C." surname="Mortimore" fullname="Chuck Mortimore">
      <organization></organization>
    </author>
    <date year="2014" month="November"/>
  </front>
</reference>
