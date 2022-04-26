%%%
title = "Cross-Device Flow Security Best Current Practice"
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

This document describes security considerations and the current best 
practices for the OAuth 2.0 Device Authorization Grant [@RFC2119]. It 
updates and extends the security considerations for the OAuth 2.0 
Device Authorization Grant with new threats and mitigations that 
reflect practical experiences gathered since it was published. 

{mainmatter}


# Introduction {#Introduction}
The OAuth Device Authroization Grant [@RFC2119] is an OAuth 2.0 [@RFC6749] 
protocol extension that enables OAuth clients to request user authorization 
from applications on devices that have limited input capabilities or lack a 
suitable browser. Such devices include smart TVs, media consoles, picture 
frames, and printers, which lack an easy input method or a suitable browser 
required for traditional OAuth interactions. 

The Device Authroization Grant flow allows the user to complete the 
authorization request on a secondary device, such as a smartphone, which 
does have the requisite input and browser capabilities to complete the user 
interaction.

Since its publication, the OAuth Device Authroization Grant [@RFC2119] has seen 
adoption in a variety of application areas that require authorization in 
scenarios with constrained input capabilities. With increased adoption and popularity, 
a number of attacks have been observed, and although some of these attacks were 
considered in the security considerations of the OAuth Device Authroization Grant 
[@RFC2119], continued exploitation demonstrates a need for more specific 
recommendations, adoption of additional mitigations, and a defense in depth.

This document provides updated security recommendations to address these 
challenges. It does not supplant the security considerations described in 
[@RFC2119], but is intended as an addition to it.

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

# The OAuth Device Authorization Grant Attacker Model
The attacker model as described in [@RFC6819] and the OAuth 2.0 Security 
Best Current Practice [insert reference] applies to the OAuth Device 
Authroization Grant. 

# Attacks and Mitigations

## Illicit Consent Grant Attack with Legitimate Device
### Threat
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

### Countermeasures


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
