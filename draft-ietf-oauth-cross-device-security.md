%%%
title = "Cross-Device Flows: Security Best Current Practice"
abbrev = "CDFS"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2", "best current practice"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-cross-device-security-latest"
stream = "IETF"
status = "bcp"


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
    email = "panva.ip@gmail.com"


%%%

.# Abstract

This document describes threats against cross-device flows
along with near term mitigations, protocol selection guidance
and the analytical tools needed to evaluate the effectiveness of
these mitigations. It serves as a security guide to system designers,
architects, product managers, security specialists, fraud analysts
and engineers implementing cross-device flows.

{mainmatter}

# Introduction {#Introduction}
Cross-device flows enable a user to initiate an authorization flow on
one device (the Initiating Device) and then use a second, personally
trusted, device (Authorization Device) to authorize the Initiating
Device to access a resource (e.g., access to a service). The Device
Authorization Grant ([@RFC8628]) and Client Initiated Backchannel
Authentication [@CIBA] are two examples of popular cross-device flows.

These flows typically involve using a mobile phone to scan a QR code
or enter a user code displayed on an Initiating Device (e.g., Smart
TV, Kiosk, Personal Computer etc).

The channel between the Initiating Device and the Authorization Device is
unauthenticated. It is up to the user to decide whether to trust
a QR code, user code, or the authorization request pushed to their Authorization
Device.

Cross-Device Consent Phishing (CDCP) attacks exploit the unauthenticated channel
between the Initiating Device and Authorization Device using social engineering
techniques to to gain unauthorized access to the user's data. Several publications
have emerged in the public domain ([@Exploit1], [@Exploit2], [@Exploit3], [@Exploit4],
[@Exploit5], [@Exploit6]), describing how the unauthenticated channel can be
exploited using social engineering techniques borrowed from phishing. Unlike traditional
phishing attacks, these attacks don't harvest credentials. Instead, they skip the
step of collecting credentials by persuading users to grant authorization using
their Authorization Devices.

Once the user grants authorization, the attacker has access to the user's
resources and in some cases is able to collect access and refresh tokens. Once in
possession of the access and refresh tokens, the attacker may use these tokens to
execute lateral attacks and gain additional access, or monetize the tokens by
selling them. These attacks are effective even when multi-factor authentication
is deployed, since the attacker's aim is not to capture and replay the credentials,
but rather to persuade the user to grant authorization.

In order to defend against these attacks, this document outlines three responses:

1. For protocols that are susceptible to Cross-Device Consent Phishing exploits, deploy practical mitigations.
3. Select protocols that are more resistant to Cross-Device Consent Phishing exploits when possible.
3. Conduct formal analysis of cross-device flows to assess susceptibility to these attacks and the effectiveness of the proposed mitigations.

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

# Cross-Device Flow Concepts
In a cross-device flow, a user starts a scenario on the Initiating Device
(e.g., a smart TV) and then uses an Authorization Device (e.g., a smartphone) to
authorize access to a resource (e.g., access to a streaming service) on
the Initiating Device.

Cross-device flows have several benefits, including:

- Authorization on devices with limited input capabilities: End-users can
authorize devices with limited input capabilities to access content (e.g.,
smart TVs, digital whiteboards, printers, etc).
- Secure authentication on shared or public devices: End-users can perform
authentication and authorization using a personally trusted device, without
risk of disclosing their credentials to a public or shared device.
- Ubiquitous multi-factor authentication: Enables a user to use multi-factor
authentication, independent of the device on which the service is being
accessed (e.g., a kiosk, smart TV or shared Personal Computer).
- Convenience of a single, portable, credential store: Users can keep all
their credentials in a mobile wallet or mobile phone that they already
carry with them.

There are three cross-device flow patterns for transferring the authorization request between the Initiating Device to the Authorization Device.

- User-Transferred Session Data Pattern: In the first pattern, the user initiates the authorization process with the authorization server by copying information from the Initiating Device to the Authorization Device, before authorizing an action. By transferring the data from the Initiating Device to the Authorization Device, the user transfers the authorization session. For example the user may read a code displayed on the Initiating Device and enter it on the Authorization Device, or they may scan a QR code displayed in the Initiating Device with the Authorization Device. The Device Authorization Grant ([@RFC8628]) is an example of a cross-device flow that follow this pattern.
- Backchannel-Transferred Session Pattern: In the second pattern, the OAuth client on the Initiating Device is responsible for transferring the session and initiating authorization on the Authorization Device via a backchannel with the Authorization Server. For example the user may attempt an online purchase on an Initiating Device (e.g. a personal computer) and receive an authorization request on their Authentication Device (e.g. mobile phone). The Client Initiated Backchannel Authentication [@CIBA] is an example of a cross-device flow that follow this pattern.
- User-Transferred Authorization Data Pattern: In the third pattern, the OAuth client on the Initiating Device triggers the authorization request via a backchannel with the Authorization Server. Authorization data (e.g. a 6 digit authorization code) is displayed on the Authorization Device, which the user enters on the Initiating Device. For example the user may attempt to access data in an enterprise application and receive a 6 digit authorization code on their Authentication Device (e.g. mobile phone) that they enter on Initiating Device.

## User-Transferred Session Data Pattern
The Device Authorization Grant ([@RFC8628]) is an example of a cross-device flow that relies on the user copying information from the Initiating Device to the Authorization Device. The figure below shows a typical example of this flow:

~~~ ascii-art
                              (B) Initiating Device
             +--------------+     Get QR/User Code  +---------------+
(A)User  +---|  Initiating  |<--------------------->|               |
   Start |   |   Device     |(E) Grant Authorization| Authorization |
   Flow  +-->|              |<--------------------->|     Server    |
             +--------------+                       |               |
                    |                               |               |
                    | (C) Scan QR code              |               |
                    |         or                    |               |
                    |   enter User Code             |               |
                    v                               |               |
             +--------------+                       |               |
             | Authorization|                       |               |
             |    Device    |<--------------------->|               |
             |              |(D) User Authenticates |               |
             |              | and Authorize Access  |               |
             +--------------+                       +---------------+
~~~
Figure: Cross-Device Flows: User-Transferred Session Data Pattern

- (A) The user takes an action on the Initiating Device by starting a purchase, adding a device to a network
or connecting a service to the Initiating Device.
- (B) The Initiating Device retrieves a QR code or user code from an Authorization Server.
- (C) The QR code or user code is displayed on the Initiating Device where the user scans the QR code
or enters the user code on the Authorization Device.
- (D) The user authenticates to the Authorization Server before granting authorization.
- (E) The Authorization Server issues tokens or grants authorization to the Initiating Device to access the user's resources.

## Backchannel-Transferred Session Pattern
The Client Initiated Backchannel Authentication [@CIBA] transfers the session on the backchannel with the Authorization Server to request authorization on the Authorization Device. The figure below shows an example of this flow.

~~~ ascii-art
                              (B) Backchannel Authorization
             +--------------+     Request           +---------------+
(A)User  +---|  Initiating  |<--------------------->|               |
   Start |   |   Device     |(E) Grant Authorization| Authorization |
   Flow  +-->|              |<--------------------->|     Server    |
             +--------------+                       |               |
                                                    |               |
                                                    |               |
                                                    |               |
                                                    |               |
(D)User                                             |               |
  Authorize  +--------------+                       |               |
  Action +---| Authorization|                       |               |
         |   |    Device    |<--------------------->|               |
         +-->|              |(C) Request User       |               |
             |              |    Authorization      |               |
             +--------------+                       +---------------+
~~~
Figure: Cross-Device Flows: Backchannel-Transferred Session Pattern

- (A) The user takes an action on the Initiating Device by starting a purchase, adding a device to a network or connecting a service to the Initiating Device.
- (B) The client on the Initiating Device requests user authorization on the backchannel from the authorization server.
- (C) The authorization server requests the authorization from the user on the user's Authorization Device.
- (D) The user authenticates to the Authorization Server before using their device to grant authorization.
- (E) The Authorization Server issues tokens or grants authorization to the Initiating Device to access the user's resources.

The Authorization Server may use a variety of mechanisms to request user authorization, including a push notification to a dedicated app on a mobile phone, or sending a text message with a link to an endpoint where the user can authenticate and authorize an action.

## User-Transferred Authorization Data Pattern
Examples of the user-transferred authorization data pattern includes flows in which the Initiating Device requests the Authorization Server to send authorization data (e.g. a 6 digit authorization code in a text message or e-mail) to the Authorization Device. Once the Authorization Device receives the authorization data, the user enters it on the Initiating Device. The Initiating Device presents it back to the Authorization Server for validation before gaining access to the user's resources. The figure below shows an example of this flow.


~~~ ascii-art
                              (B) Backchannel Authorization
             +--------------+     Request           +---------------+
(A)User  +---|  Initiating  |<--------------------->|               |
   Start |   |   Device     |(E) Grant Authorization| Authorization |
   Flow  +-->|              |<--------------------->|     Server    |
             +--------------+                       |               |
                    ^                               |               |
                    | (D)User Enters                |               |
                    |    Authorization Data         |               |
                    |                               |               |
                    |                               |               |
             +--------------+                       |               |
             | Authorization|                       |               |
             |    Device    |<--------------------->|               |
             |              |(C) Send Authorization |               |
             |              |    Data               |               |
             +--------------+                       +---------------+
~~~
Figure: Cross-Device Flow: User-Transferred Authorization Data Pattern

- (A) The user takes an action on the Initiating Device by starting a purchase, adding a device to a network or connecting a service to the Initiating Device.
- (B) The client on the Initiating Device requests user authorization on the backchannel from the authorization server.
- (C) The authorization server sends authorization data (e.g. a 6 digit authorization code) to the Authorization Device.
- (D) The user enters the authorization data (e.g. the 6 digit authorization code) on the Initiating Device.
- (E) The Authorization Server issues tokens or grants authorization to the Initiating Device to access the user's resources.

The Authorization Server may choose to authenticate the user before sending the authorization data. The authorization data may be delivered as a text message or through a mobile application.

## Examples of Cross-Device Flows
Examples of cross-device flow scenarios include:

### Example A1: Authorize Access to a Video Streaming Service (User-Transferred Session Data Pattern)
An end-user sets up a new smart TV and wants to connect it to their favorite streaming service. The TV displays a QR code that the user scans with their mobile phone. The user is redirected to the streaming service provider's web page and asked to enter their credentials to authorize the smart TV to access the streaming service. The user enters their credentials and grants authorization, after which the streaming service is available on the smart TV.

### Example A2: Authorize Access to Productivity Services (User-Transferred Session Data Pattern)
An employee wants to access their files on an interactive whiteboard in a conference room. The interactive whiteboard displays a URL and a code. The user enters the URL on their personal computer and is prompted for the code. Once they enter the code, the user is asked to authenticate and authorize the interactive whiteboard to access their files. The user enters their credentials and authorizes the transaction and the interactive whiteboard retrieves their files and allows the user to interact with the content.

### Example A3: Authorize Use of a Bike Sharing Scheme (User-Transferred Session Data Pattern)
An end-user wants to rent a bicycle from a bike sharing scheme. The bicycles are locked in bicylce racks on sidewalks throughout a city. To unlock and use a bicycle, the user scans a QR code on the bicycle using their mobile phone. Scanning the QR code redirects the user to the bicycle sharing scheme's authorization page where the user authenticates and authorizes payment for renting the bicycle. Once authorized, the bicycle sharing service unlocks the bicycle, allowing the user to use it to cycle around the city.

### Example A4: Authorize a Financial Transaction (Backchannel-Transferred Session Pattern)
An end-user makes an online purchase. Before completing the purchase, they get a notification on their mobile phone, asking them to authorize the transaction. The user opens their app and authenticates to the service before authorizing the transaction.

### Example A5: Add a Device to a Network (User-Transferred Authorization Data Pattern)
An employee is issued with a personal computer that is already joined to a network. The employee wants to add their mobile phone to the network to allow it to access corporate data and services (e.g., files and e-mail). The employee is logged-in on the personal computer where they initiate the process of adding their mobile phone to the network. The personal computer displays a QR code which authorizes the user to join their mobile phone to the network. The employee scans the QR code with their mobile phone and the mobile phone is joined to the network. The employee can start accessing corporate data and services on their mobile device.

### Example A6: Remote Onboarding (User-Transferred Session Data Pattern)
A new employee is directed to an onboarding portal to provide additional information to confirm their identity on their first day with their new employer. Before activating the employee's account, the onboarding portal requests that the employee present a government issued ID, proof of a background check and proof of their qualifications. The onboarding portal displays a QR code, which the user scans with their mobile phone. Scanning the QR code invokes the employee's digital wallet on their mobile phone, and the employee is asked to present digital versions of an identity document (e.g., a driving license), proof of a background check by an identity verifier, and proof of their qualifications. The employee authorizes the release of the credentials and after completing the onboarding process, their account is activated.

### Example A7: Application Bootstrap (User-Transferred Authorization Data Pattern)
An employee is signed into an application on their personal computer and wants to bootstrap the mobile application on their mobile phone. The employee initiates the cross-device flow and is shown a QR code in their application. The employee launches the mobile application on their phone and scans the QR code which results in the user being signed into the application on the mobile phone.

### Example A8: Access a Productivity Application (User-Transferred Authorization Data Pattern)
A user is accessing a Computer Aid Design (CAD) application. When accessing the application, authorization data in the form of a 6 digit authorization code is sent to the user's mobile phone. The user views the 6 digit authorization code on their phone and enters it in the CAD application, after which the CAD application displays the user's most recent designs.

# Cross-Device Flow Exploits
Attackers exploit cross-device flows by initiating an authorization flow on the Initiating Device and then use social engineering techniques to change the context in which the request is presented to the user in order to convince them to grant authorization on the Authorization Device. The attacker is able to change the context of the authorization request because the channel between the Initiating Device and the Authorization Device is unauthenticated. These attacks are also known as Cross-Device Consent Phishing (CDCP) attacks.

## User-Transferred Session Data Pattern Exploits
A common action in cross-device flows is to present the user with a QR code or a user code on the Initiating Device (e.g., Smart TV) which is then scanned or entered on the Authorization Device (the mobile phone). When the user scans the code or copies the user code, they do so without any proof that the QR code or user code is being displayed in the place or context intended by the service provider. It is up to the user to decide whether they should trust the QR code or user code. In effect the user is asked to compensate for the absence of an authenticated channel between the Initiating Device (e.g., smart TV) and the Authorization Device (e.g., the mobile phone).

Attackers exploit this absence of an authenticated channel between the two devices by obtaining QR codes or user codes (e.g., by initiating the authorization flows). They then use social engineering techniques to change the context in which authorization is requested to convince end-users to scan the QR code or enter it on their Authorization Device (e.g., mobile phone). Once the end-user performs the authorization on the mobile device, the attacker who initiated the authentication or authorization request obtains access to the users resources. The figure below shows an example of such an attack.

~~~ ascii-art
                           (B) Initiating Device
           +--------------+     Get QR/User Code  +---------------+
           |  Attacker's  |<--------------------->|               |
           |  Initiating  |(G) Grant Authorization| Authorization |
           |   Device     |<--------------------->|     Server    |
           +--------------+                       |               |
             ^   | (C) Attacker Copy              |               |
(A) Attacker |   |     QR or User Code            |               |
    Start    |   |                                |               |
    Flow     |   V                                |               |
           +--------------+                       |               |
           |              |                       |               |
           |   Attacker   |                       |               |
           |              | (D) Attacker Change   |               |
           |              |     QR Code/User Code |               |
           |              |     Context           |               |
           +--------------+                       |               |
                  | (E) User is convinced by the  |               |
                  |     attacker and scans QR code|               |
                  |     or enters User Code       |               |
                  v                               |               |
           +--------------+                       |               |
           |   End User   |                       |               |
           | Authorization|                       |               |
           |    Device    |<--------------------->|               |
           |              |(F) User Authenticates |               |
           |              | and Authorize Access  |               |
           +--------------+                       +---------------+
~~~
Figure: Cross-Device Consent Phishing: User-Transferred Session Data Pattern

- (A) The attacker initiates the protocol on the Initiating Device (or mimicks the Initiating Device) by starting a purchase, adding a device to a network or connecting a service to the Initiating Device.
- (B) The Initiating Device retrieves a QR code or user code from an Authorization Server.
- (C) The attacker copies the QR code or user code.
- (D) The attacker changes the context in which the QR code or user code is displayed in such a way that the user is likely to scan the QR code or use the user code when completing the authorization. For example, the attacker could craft an e-mail that includes the user code or QR code and send it to the user. The e-mail might encourage the user to scan the QR code or enter the user code by suggesting that doing so would grant them a reward through a loyalty program or prevent the loss of their data.
- (E) The QR code or user code is displayed to the user in a context chosen by the attacker. The user is convinced by the attacker's effort and scans the QR code or enters the user code on the Authorization Device.
- (F) The user authenticates to the Authorization Server before granting authorization.
- (G) The Authorization Server issues tokens or grants authorization to the Initiating Device, which is under the attacker's control, to access the user's resources. The attacker gains access to the resources and any authorization artifacts (like access and refresh tokens) which may be used in future exploits.

## Backchannel-Transferred Session Pattern Exploits
In the backchannel-transferred session pattern, the client requests the authorization server to authenticate the user and obtain authorization for an action. This may happen as a result of user interaction with the Initiating Device, but may also be triggered without the users direct interaction with the Initiating Device, resulting in an authorization request presented to the user without context of why or who triggered the request.

Attackers exploit this lack of context by using social engineering techniques to prime the user for an authorization request and thereby convince them to granting authorization. The social engineering techniques range in sophistication from messages misrepresenting the reason for receiving an authorization request, to triggering a large volume of requests at an inconvenient time for the user, in the hope that the user will grant authorization to make the requests stop. The figure below shows an example of such an attack.

~~~ ascii-art
                              (C) Backchannel Authorization
             +--------------+     Request           +---------------+
             |  Attacker's  |<--------------------->|               |
             |  Initiating  |(F) Grant Authorization| Authorization |
             |  Device      |<--------------------->|     Server    |
             +--------------+                       |               |
               ^                                    |               |
  (B) Attacker |                                    |               |
      Starts   |                                    |               |
      Flow     |                                    |               |
             +--------------+                       |               |
             |              |                       |               |
             |   Attacker   |                       |               |
             |              |                       |               |
             |              |                       |               |
             |              |                       |               |
             +--------------+                       |               |
                    |  (A) Attacker Sends           |               |
                    |       Social Engineering      |               |
                    |       Message to User         |               |
                    |                               |               |
(E)User             v                               |               |
  Authorize  +--------------+                       |               |
  Action +---| Authorization|                       |               |
         |   |    Device    |<--------------------->|               |
         +-->|              |(D) Request User       |               |
             |              |    Authorization      |               |
             +--------------+                       +---------------+
~~~
Figure: Cross-Device Consent Phishing: Backchannel-Transferred Session Pattern

- (A) The attacker sends a social engineering message to prepare the user for the upcoming authorization (optional).
- (B) The attacker initiates the protocol on the Initiating Device (or by mimicking the Initiating Device) by starting a purchase, adding a device to a network or accessing a service on the Initiating Device.
- (C) The client on the Initiating Device requests user authorization on the backchannel from the Authorization Server.
- (D) The Authorization Server requests the authorization from the user on the user's device.
- (E) The user authenticates to the authorization server before granting authorization on their device.
- (G) The Authorization Server issues tokens or grants authorization to the Initiating Device, which is under the attacker's control. The attacker gains access to the user's resources and possibly any authorization artifacts like access and refresh tokens.

## User-Transferred Authorization Data Pattern Exploits
In cross-device flows that follow the user-transferred authorization data pattern, the client on the Initiating Device initiates the authorization request, but the user still has to transfer the authorization data to the Initiating Device. The authorization data may take different forms, including a numerical value such as a 6 digit authorization code. The authorization request may happen as a result of user interaction with the Initiating Device, but may also be triggered without the user's direct interaction with the Initiating Device.

Attackers exploit the user-transferred authorization data pattern by combining the social engineering techniques used to set context for users and convincing users to providing them with authorization data sent to their Authorization Devices (e.g. mobile phones). These attacks are very similar to phishing attacks, except that the attacker also has the ability to trigger the authorization request to be sent to the user directly by the Authorization Server.

~~~ ascii-art
                              (C) Backchannel Authorization
             +--------------+     Request           +---------------+
             |  Attacker's  |<--------------------->|               |
             |  Initiating  |(G) Grant Authorization| Authorization |
             |  Device      |<--------------------->|     Server    |
             +--------------+                       |               |
               ^       ^                            |               |
  (B) Attacker |       | (F) Attacker Forwards      |               |
      Starts   |       |     Authorization Data     |               |
      Flow     |       |                            |               |
             +--------------+                       |               |
             |              |                       |               |
             |   Attacker   |                       |               |
             |              |                       |               |
             |              |                       |               |
             |              |                       |               |
             +--------------+                       |               |
(A) Attacker    |       ^   (E) User                |               |
    Sends       |       |       Sends               |               |
    Social      |       |       Authorization Data  |               |
    Engineering |       |                           |               |
    Message     |       |                           |               |
                v       |                           |               |
             +--------------+                       |               |
             | Authorization|                       |               |
             |    Device    |<--------------------->|               |
             |              |(D) Send Authorization |               |
             |              |    Data               |               |
             +--------------+                       +---------------+
~~~
Figure: Cross-Device Consent Phishing: User-Transferred Authorization Data Pattern

- (A) The attacker sends a social engineering message to prime the user for the authorization request they are about to receive, including instructions on what to do with the authorization data once they receive it.
- (B) The attacker initiates the protocol on the Initiating Device (or by mimicking the Initiating Device) by starting a purchase, adding a device to a network or accessing a service on the Initiating Device.
- (C) The client on the Initiating Device requests user authorization on the backchannel from the Authorization Server.
- (D) The Authorization Server sends authorization data (e.g. a 6 digit authorization code) to the user's Authorization Device (the authorization data may be presented as a QR code, or text message).
- (E) The user is convinced by the social engineering message received in step (A) and forwards the authorization data (e.g. a 6 digit authorization code) to the attacker.
- (F) The attacker enters the authorization data (e.g. a 6 digit authorization code) on the Initiating Device.
- (G) The Authorization Server grants authorization and issues access and refresh tokens to the Initiating Device, which is under the attacker's control. On completion of the exploit, the attacker gains access to the user's resources.

The unauthenticated channel may also be exploited in variations of the above scenario where the user (as opposed to the attacker) initiates the flow  and is then convinced using social engineering techniques into sending the authorization data (e.g. a 6 digit authorization code) to the attacker. In these flows, the user is already authenticated and they request authorization data to transfer a session or obtain some other privilege such as joining a device to a network. The authorization data may be represented as a QR code or text string (e.g. 6 digit authorization code). The attacker then proceeds to exploit the unauthenticated channel by using social engineering techniques to convince the user to send the QR code or user code to the attacker. The attacker then use the authorization data to obtain the privileges that would have been assigned to the user.

## Examples of Cross-Device Consent Phishing Attacks
The following examples illustrate these attacks in practical settings and show how the unauthenticated channel is exploited by attackers who can copy the QR codes and user codes, change the context in which they are presented using social engineering techniques and mislead end-users into granting consent to avail of services, access data and make payments.

### Example B1: Illicit access to a video streaming service (User-Transferred Session Data Pattern)
An attacker obtains a smart TV and attempts to access an online streaming service. The smart TV obtains a QR code from the authorization server and displays it on screen. The attacker copies the QR code and embeds it in an e-mail that is sent to a large number of recipients. The e-mail contains a message stating that the streaming service wants to thank them for their loyal support and by scanning the QR code, they will be able to add a bonus device to their account for no charge. One of the recipients open the e-mail and scan the QR code to claim the loyalty reward. The user performs multi-factor authentication, and when asked if they want a new device to be added to their account, they authorize the action. The attacker's device is now authorized to access the content and obtains an access and refresh token. The access token allows the attacker to access content and the refresh token allows the attacker to obtain fresh tokens whenever the access token expires.

The attacker scales up the attack by emulating a new smart TV, obtaining multiple QR codes and widening the audience it sends the QR code to. Whenever a recipient scans the QR code and authorizes the addition of a new device, the attacker obtains an access and refresh token, which they sell for a profit.

### Example B2: Illicit Access to Productivity Services (User-Transferred Session Data Pattern)
An attacker emulates an enterprise application (e.g., an interactive whiteboard) and initiates a cross-device flow by requesting a user code and URL from the authorization server. The attacker obtains a list of potential victims and sends an e-mail informing users that their files will be deleted within 24 hours if they don't follow the link, enter the user code and authenticate. The e-mail reminds them that this is the third time that they have been notified and their last opportunity to prevent deletion of their work files. One or more employees respond by following the URL, entering the code and performing multi-factor authentication. Throughout the authentication experience, the user is interacting with a trusted user experience, re-enforcing the legitimacy of the request. Once these employees authorized access, the attacker obtains access and refresh tokens from the authorization server and uses it to access the users' files, perform lateral attacks to obtain access to other information and continuously refresh the session by requesting new access tokens. These tokens may be exfiltrated and sold to third parties.

### Example B3: Illicit Access to Physical Assets (User-Transferred Session Data Pattern)
An attacker copies a QR code from a bicycle locked in a bicycle rack in a city, prints it on a label and places the label on a bicycle at the other end of the bicycle rack. A customer approaches the bicycle that contains the replicated QR code and scans the code and authenticates before authorizing payment for renting the bicycle. The bicycle rack unlocks the bicycle containing the original QR code and the attacker removes the bicycle before cycling down the street while the customer is left frustrated that the bicycle they were trying to use is not being unlocked [@NYC.Bike]. The customer proceeds to unlock another bicycle and lodges a complaint with the bicycle renting company.

### Example B4: Illicit Transaction Authorization (Backchannel-Transferred Session Pattern)
An attacker obtains a list of user identifiers for a financial institution and triggers a transaction request for each of the users on the list. The financial institution's authorization server sends push notifications to each of the users, requesting authorization of a transaction. The vast majority of users ignore the request to authorize the transaction, but a small percentage grants authorization by approving the transaction.

### Example B5: Illicit Network Join (User-Transferred Authorization Data Pattern)
An attacker creates a message to all employees of a company, claiming to be from a trusted technology provider investigating a suspected security breach. They ask employees to send them the QR code typically used to join a new device to the network, along with detailed steps on how to obtain the QR code. The employee, eager to assist, initiates the process to add a new mobile device to the network. They authenticate to the network and obtain a QR code. They send the QR code to the attacker. The attacker scans the QR code and adds their own device to the network. They use this device access as an entry point and perform lateral moves to obtain additional privileges and access to restricted resources.

### Example B6: Illicit Onboarding (User-Transferred Session Data Pattern)
An attacker initiates an employee onboarding flow and obtains a QR code from the onboarding portal to invoke a digital wallet and present a verifiable credential attesting to a new employee's identity. The attacker obtains a list of potential new employees and sends an e-mail informing them that it is time to present proof of their background check or government issued ID. The new employee scans the QR code, invokes their digital wallet and presents their credentials. Once the credentials are presented, the employee's account is activated. The employee portal accessed by the attacker to obtain the QR code displays a message to the attacker with instructions on how to access their account.

### Example B7: Illicit Application Bootstrap (User-Transferred Authorization Data Pattern)
An attacker creates a message to all employees of a company, claiming to be from the company's IT service provider. They claim that they are trying to resolve an application performance issue and ask employees to send them the QR code typically used to transfer a session. The employee, eager to assist, initiates the process to transfer a session. They authenticate and obtain a QR code and then send the QR code to the attacker. The attacker scans the QR code with their mobile phone and access the users data and resources.

### Example B8: Account Takeover (User-Transferred Session Data Pattern)
An attacker wants to use some website which requires presentation of a verifiable credential for authentication. The attacker creates a phishing website which will in real time capture log-in QR Codes from the original website and present these to the user. The attacker tries to get the user to use the phishing website using an e-mail campaign etc. The user scans the QR code on the phishing website, invokes their digital wallet and presents their credentials. Once the credentials are presented, the original session from the attackers device is authorized with the user's credentials.

### Out of Scope
In all of the attack scenarios listed above, a user is misled or exploited. For other attacks, where the user is willingly colluding with the attacker, the threat model, security implications and potential mitigations are very different. For example, a cooperating user can bypass software mitigations on their device, share access to hardware tokens with the attacker, and install additional devices to forward radio signals to circumvent proximity checks.

This document only considers scenarios where a user does not collude with an attacker.

# Cross-Device Protocols and Standards
Cross-device flows that are subject to the attacks described earlier, typically share the following characteristics:

1.	The attacker can initiate the flow and manipulate the context of an authorization request.
    E.g. the attacker can obtain a QR code or user code, or can request an authentication/authorization decision from the user.
2.	The interaction between the Initiating Device and Authorization Device is unauthenticated.
    E.g. it is left to the user to decide if the QR code, user code or authentication request is being presented in a legitimate context

A number of protocols that have been standardized, or are in the process of being standardized that share these characteristics include:

- IETF OAuth 2.0 Device Authorization Grant ([@RFC8628]): A standard to enable authorization on devices with constrained input capabilities (smart TVs, printers, kiosks). In this protocol, the user code or QR code is displayed on the Initiating Device and entered on a second device (e.g., a mobile phone).

- Open ID Foundation Client Initiated Back-Channel Authentication (CIBA) [@CIBA]: A standard developed in the OpenID Foundation that allows a device or service (e.g., a personal computer, Smart TV, Kiosk) to request the OpenID Provider to initiate an authentication flow if it knows a valid identifier for the user. The user completes the authentication flow using a second device (e.g., a mobile phone). In this flow the user does not scan a QR code or obtain a user code from the Initiating Device, but is instead contacted by the OpenID Provider to complete the authentication using a push notification, e-mail, text message or any other suitable mechanism.

- OpenID for Verifiable Credential Protocol Suite (Issuance, Presentation): The OpenID for Verifiable Credentials enables cross-device scenarios by allowing users to scan QR codes to retrieve credentials (Issuance) or present credentials (Presentation). The QR code is presented on a device that initiates the flow.

- Self-Issued OpenID Provider v2 (SIOP V2): A standard that allows end-user to present self-attested or third party attested attributes when used with OpenID for Verifiable Credential protocols. The user scans a QR code presented by the relying party to initiate the flow.

Cross-device protocols SHOULD not be used for same-device scenarios. If the Initiating Device and Authorization Device are the same device, protocols like OpenID Connect Core [@OpenID.Core] and OAuth 2.0 Authorization Code Grant as defined in [@RFC6749] are more appropriate. If a protocol supports both same-device and cross-device modes (e.g. [@OpenID.SIOPV2]), the cross-device mode SHOULD not be used for same-device scenarios. If an implementor decides to use a cross-device protocol or a protocol with a cross-device mode in a same-device scenario, the mitigations recommended in this document SHOULD be implemented to reduce the risks that the unauthenticated channel is exploited.

# Mitigating Against Cross-Device Flow Attacks
The unauthenticated channel between the Initiating Device and the Authorization Device allows attackers to change the context in which the authorization request is presented to the user. This shifts responsibility of authenticating the channel between the two devices to the end-user. End-users have "expertise elsewhere" and are typically not security experts and don't understand the protocols and systems they interact with. As a result, end-users are poorly equipped to authenticate the channel between the two devices. Mitigations should focus on:

1.	Minimizing reliance on the user to make decisions to authenticate the channel.
2.	Providing better information with which to make decisions to authenticate the channel.
3.	Recovering from incorrect channel authentication decisions by users.

To achieve the above outcomes, mitigating against Cross-Device Consent Phishing attacks require a three-pronged approach:

1.	Reduce risks of deployed protocols with practical mitigations.
2.	Adopt or develop protocols that are less susceptible to these attacks where possible.
3.	Provide analytical tools to assess vulnerabilities and effectiveness of mitigations.

## Practical Mitigations

A number of protocols that enable cross-device flows that are susceptible to Cross-Device Consent Phishing attacks are already deployed. The security profile of these protocols can be improved through practical mitigations that provide defense in depth that either:

1.	Prevents the attack from being initiated.
2.	Disrupts the attack once it is initiated.
3.	Remediates or reduces the impact if the attack succeeds.

It is RECOMMENDED that one or more of the mitigations are applied whenever implementing a cross-device flow. Every mitigation provides an additional layer of security that makes it harder to initiate the attack, disrupts attacks in progress or reduces the impact of a successful attack.

### Establish Proximity
The unauthenticated channel between the Initiating Device and Authorization Device allows attackers to obtain a QR code or user code in one location and display it in another location. Consequently, proximity-enforced cross-device flows are more resistant to Cross-Device Consent Phishing attacks than proximity-less cross-device flows. Establishing proximity between the location of the Initiating Device and the Authorization Device limits an attacker's ability to launch attacks by sending the user or QR codes to large numbers of users that are geographically distributed. There are a couple of ways to establish proximity:

- Physical connectivity: This is a good indicator of proximity, but requires specific ports, cables and hardware and may be challenging from a user experience perspective or may not be possible in certain settings (e.g., when USB ports are blocked or removed for security purposes). Physical connectivity may be better suited to dedicated hardware like FIDO devices that can be used with protocols that are resistant to the exploits described in this document.

- Wireless proximity: Near Field Communications (NFC), Bluetooth Low Energy (BLE), and Ultra Wideband (UWB) services can be used to prove proximity between the two devices. NFC technology is widely deployed in mobile phones as part of payment solutions, but NFC readers are less widely deployed. BLE presents another alternative for establishing proximity, but may present user experience challenges when setting up. UWB standards such as IEEE  802.15.4 and the IEEE 802.15.4z-2020 Amendment 1 enable secure ranging between devices and allow devices to establish proximity relative to each other [@IEEE802154].

- Shared network: Device proximity can be inferred by verifying that both devices are on the same network. This check may be performed by the authorization server by comparing the network addresses of the device where the code is displayed (Initiating Device) with that of the Authorization Device. Alternatively the check can be performed on the device, provided that the network address is available. This could be achieved if the authorization server encodes the Initiating Device's network address in the QR code and uses a digital signature to prevent tampering with the code. This does require the wallet to be aware of the countermeasure and effectively enforce it.

- Geo-location: Proximity can be established by comparing geo-location information derived from global navigation satellite-system (GNSS) co-ordinates or geolocation lookup of IP addresses and comparing proximity. Due to inaccuracies, this may require restrictions to be at a more granular level (e.g., same city, country, region or continent). Similar to the shared network checks, these checks may be performed by the authorization server or on the users device, provided that the information encoded in a QR code is integrity protected using a digital signature.

Depending on the risk profile and the threat model in which a system is operating, it MAY be necessary to use more than one mechanism to establish proximity to raise the bar for any potential attackers.

Note: There are scenarios that require that an authorization takes place in a different location than the one in which the transaction is authorized. For example, there may be a primary and secondary credit card holder and both can initiate transactions, but only the primary holder can authorize it. There is no guarantee that the primary and secondary holders are in the same location at the time of the authorization. In such cases, proximity (or lack of proximity) may be an indicator of risk and the system may deploy additional controls (e.g., transaction value limits, transaction velocity limits) or use the proximity information as input to a risk management system.

**Limitations:** Proximity mechanisms make it harder to perform Cross-Device Consent Phishing (CDCP) attacks. However, depending on how the proximity check is performed, an attacker may be able to circumvent the protection: The attacker can use a VPN to simulate a shared network or spoof a GNSS position. For example, the attacker can try to request the location of the end-user's Authorization Device through browser APIs and then simulate the same location on their Initiating Device using standard debugging features available on many platforms.

### Short Lived/Timebound QR or User Codes
The impact of an attack can be reduced by making QR or user codes short lived. If an attacker obtains a short lived code, the duration during which the unauthenticated channel can be exploited is reduced, potentially increasing the cost of a successful attack.

**Limitations:** There is a practical limit to how short a user code can be valid due to network latency and user experience limitations (time taken to enter a code, or incorrectly entering a code). More sophisticated Cross-Device Consent Phishing attacks counter the effectiveness of short lived codes by convincing a user to respond to a phishing e-mail and only request the QR or user code once the user clicks on the link in the phishing e-mail [@Exploit6].

### One-Time or Limited Use Codes
By enforcing one-time use or limited use of user or QR codes, the authorization server can limit the impact of attacks where the same user code or QR code is sent to multiple victims. One-time use may be achieved by including a nonce or date-stamp in the user code or QR code which is validated by the authorization server when the user scans the QR code against a list of previously issued codes.

**Limitations:** Enforcing one-time use may be difficult in large globally distributed systems with low latency requirements, in which case short lived tokens may be more practical. One-time use codes may also have an impact on the user experience. For example, a user may enter a code, but their session may be interrupted before the access request is completed. If the code is a one-time use code, they would need to restart the session and obtain a new code since they won't be allowed to enter the same code a second time. To avoid this, implementers MAY allow the same code to be presented a small number of times.

### Unique Codes
By issuing unique user or QR codes, an authorization server can detect if the same codes are being repeatedly submitted. This may be interpreted as anomalous behavior and the authorization server MAY choose to decline issuing access and refresh tokens if it detects the same codes being presented repeatedly. This may be achieved by maintaining a deny list that contains QR codes or user codes that were previously used. The authorization server MAY use a sliding window equal to the lifetime of a token if short lived/timebound tokens are used (see [Short Lived/Timebound Codes](#Short Lived/Timebound Codes)). This will limit the size of the deny list.

**Limitations:** Maintaining a deny list of previously redeemed codes, even for a sliding window, may have an impact on the latency of globally distributed systems. One alternative is to segment user codes by geography or region and maintain local deny lists.

### Content Filtering
Attackers exploit the unauthenticated channel by changing the context of the user code or QR code and then sending a message to a user (e-mail, text, instant messaging etc). By deploying content filtering (e.g., anti-spam filter), these messages can be blocked and prevented from reaching the end-users. It may be possible to fine-tune content filtering solutions to detect artefacts like QR codes or user codes that are included in a message that is sent to multiple recipients in the expectation that at least one of the recipients will be convinced by the message and grant authorization to access restricted resources.

**Limitations:** Some scenarios may require legitimate re-transmission of user, QR and authorization data (e.g. retries). To prevent the disruption of legitimate scenarios, content filters may use a threshold and allow a limited number of messages with the same QR or user codes to be transmitted before interrupting the delivery of those messages. Content filtering may also be fragmented across multiple communications systems and channels (e-mail, messaging, text etc), making it harder to detect or interrupt attacks that are executed over multiple channels, unless here is a high degree of integration between content filtering systems.

### Detect and Remediate
The authorization server may be able to detect misuse of the codes due to repeated use as described in [Unique Codes](#Unique Codes), as an input from a content filtering engine as described in [Content Filtering](#Content Filtering), or through other mechanisms such as reports from end-users. If an authorization server determines that a user code or QR code is being used in an attack it may choose to invalidate all tokens issued in response to these codes and make that information available through a token introspection endpoint (see [@RFC7662]). In addition it may notify resource servers to stop accepting these tokens or to terminate existing sessions associated with these tokens using Continuous Access Evaluation Protocol (CAEP) messages [@CAEP] using the Shared Signals Framework (SSF) [@SSF] framework or an equivalent notification system.

**Limitations:** Detection and remediation requires that resource servers are integrated with security eventing systems or token introspection services. This may not always be practical for existing systems and may need to be targeted to the most critical resource services in an environment.

### Trusted Devices
If an attacker is unable to initiate the protocol, they are unable to obtain a QR code or user code that can be leveraged for the attacks described in this document. By restricting the protocol to only be executed on devices trusted by the authorization server, it prevents attackers from using arbitrary devices, or by mimicking devices to initiate the protocol. Trusted devices include devices that are pre-registered with the authorization server or are subject to device management policies. Device management policies may enforce patching, version updates, on-device anti-malware deployment, revocation status and device location amongst others. Trusted devices may have their identities rooted in hardware (e.g., a TPM or equivalent technology). By only allowing trusted devices to initiate cross-device flows, it requires the attacker to have access to such a device and maintain access in a way that does not result in the device's trust status from being revoked.

**Limitations:** An attacker may still be able to obtain access to a trusted device and use it to initiate authorization requests, making it necessary to apply additional controls and integrating with other threat detection and management systems that can detect suspicious behaviour such as repeated requests to initiate authorization or high volume of service activation on the same device.

### Trusted Networks
An attacker can be prevented from initiating a cross-device flow protocol by only allowing the protocol to be initiated on a trusted network or within a security perimeter (e.g., a corporate network). A trusted network may be defined as a set of IP addresses and joining the network is subject to security controls managed by the network operator, which may include only allowing trusted devices on the network, device management, user authentication and physical access policies and systems. By limiting protocol initiation to a specific network, the attacker needs to have access to a device on the network.

**Limitations:** Network level controls may not always be feasible, especially when dealing with consumer scenarios where the network may not be under control of the service provider. Even if it is possible to deploy network level controls, it SHOULD be used in conjunction with other controls outlined in this document to achieve defence in-depth.

### Limited Scopes
Authorization servers MAY choose to limit the scopes they include in access tokens issued through cross-device flows where the unauthenticated channel between two devices are susceptible to being exploited. Including limited scopes lessens the impact in case of a successful attack. The decision about which scopes are included may be further refined based on whether the protocol is initiated on a trusted device or the user's location relative to the Initiating Device.

**Limitations:** Limiting scopes reduces the impact of a compromise, but does not avoid it. It SHOULD be used in conjunction with other mitigations described in this document.

### Short Lived Tokens
Another mitigation strategy includes limiting the life of the access and refresh tokens. The lifetime can be lengthened or shortened, depending on the user's location, the resources they are trying to access or whether they are using a trusted device. Short lived tokens do not prevent or disrupt the attack, but serve as a remedial mechanism in case the attack succeeded.

**Limitations:** Short lived tokens reduces the time window during which an attacker can benefit from a successful attack. This is most effective for access tokens. However, once an attacker obtains a refresh token, they can continue to request new access tokens, as well as refresh tokens. Forcing the expiry of refresh tokens may cause the user to re-authorize an action more frequently, which results in a negative user experience.

### Rate Limits
An attacker that engages in a scaled attack may need to request a large number of user codes (see exploit [Example B1](#Example B1: Illicit access to a video streaming service (User-Transferred Session Data Pattern))) or initiate a large number of authorization requests (see exploit [Example B4](#Example B4: Illicit Transaction Authorization (Backchannel-Transferred Session Pattern))) in a short period of time. An authorization server MAY apply rate limits to minimize the number of requests it would accept from a client in a limited time period.

**Limitations:** Rate limits are effective at slowing an attacker down and help to degrade scaled attacks, but do not prevent more targeted attacks that are executed with lower volumes and velocity. Therefore, it should be used along with other techniques to provide a defence-in-depth defence against cross-device attacks.

### Sender-Constrained Tokens
Sender-constrained tokens limit the impact of a successful attack by preventing the tokens from being moved from the device on which the attack was successfully executed. This makes attacks where an attacker gathers a large number of access and refresh tokens on a single device and then sells them for profit more difficult, since the attacker would also have to export the cryptographic keys used to sender-constrain the tokens or be able to access them and generate signatures for future use. If the attack is being executed on a trusted device to a device with anti-malware, any attempts to exfiltrate tokens or keys may be detected and the device's trust status may be changed. Using hardware keys for sender-constraining tokens will further reduce the ability of the attacker to move tokens to another device.

**Limitations:** Sender-constrained tokens, especially sender-constrained tokens that require proof-of-posession, raise the bar for executing the attack and profiting from exfiltrating tokens. Although a software proof-of-posession key is better than no proof-of-posession key, an attacker may still exfiltrate the software key. Hardware keys are harder to exfiltrate, but come with additional implementation complexity. An attacker that controls the Initiating Device may still be able to excercise the key, even if it is in hardware. Consequently the main protection derived from sender-constrained tokens is preventing tokens from being moved from the Initiating Device to another device, thereby making it harder sell stolen tokens and profit from the attack.

### User Education
Research shows that user education is effective in reducing the risk of phishing attacks [@Baki2023]. The service provider MAY educate users on the risks of cross-device consent phishing and provide out-of-band reinforcement to the user on the context and conditions under which an authorization grant may be requested. For example, if the service provider does not send e-mails with QR codes requesting users to grant authorization, this may be reinforced in marketing messages and anti-fraud awareness campaigns. The service provider MAY also choose to reinforce these user education messages through in-app experiences.

**Limitations:** Although user education helps to raise awareness and reduce the overall risk to users, it is insufficient on its own to mitigate cross-device consent phishing attacks. In particular, carefully designed phishing attacks can be practically indistinguishable from benign authorization flows even for well-trained users. User education SHOULD therefore be used in conjunction with other controls described in this document.

### User Experience
The user experience SHOULD preserve the context within which the protocols were initiated and communicate this clearly to the user when they are asked to authorize, authenticate or present a credential. In preserving the context, it should be clear to the user who invoked the flow, why it was invoked and what the consequence of completing the authorization, authentication or credential presentation is. The user experience should reinforce the message that unless the user initiated the authorization request, or was expecting it, they should decline the request.

If the user uses an application on a mobile device to scan a QR code, the application MAY display information advising the user under which conditions they should expect to be asked to scan a QR code and under which circumstances they should never scan a QR code (e.g. display a message that the QR code will only be displayed on kiosks within trusted locations or on trusted websites hosted on a specific domain, and never in e-mail or other media and locations).

It SHOULD be clear to the user how to decline the request. To avoid accidental authorization grants, the "decline" option SHOULD be the default option or given similar prominence in the user experience as the "grant" option.

The user experience MAY include information to further educate the user on cross-device consent phishing attacks and reinforce the conditions under which authorization grants may be requested.

This information may be communicated graphically or in a simple message (e.g., "It looks like you are trying to access your files on a digital whiteboard in your city center office. Click here to grant access to your files. If you are not trying to access your files, you should decline this request and notify the security department").

**Limitations:** Improvements to user experience on their own is unlikely to be sufficient and SHOULD be used in conjunction with other controls described in this document.

### Authenticated flow
By requiring a user to authenticate on the Initiating Device with a phishing resistant authentication method before initiating a cross-device flow, the server can prevent an attacker from initiating a cross-device flow and obtaining QR codes or user codes. This prevents the attacker from obtaining a QR code or user code that they can use to mislead an unsuspecting user. This requires that the Initiating Device has sufficient input capabilities to support a phishing resistant authentication mechanism, which may in itself negate the need for a cross-device flow.

**Limitations:** Starting with an authenticated flow does not prevent the attacks described in [Example B5: Illicit Network Join](#Example B5: Illicit Network Join (User-Transferred Authorization Data Pattern)) and [Example B7: Illicit Session Transfer](#Example B7: Illicit session transfer (User-Transferred Authorization Data Pattern)) and it is RECOMMENDED that additional mitigations described in this document is used if the cross-device flows are used in scenarios such as [Example A5: Add a device to a network](#Example A5: Add a device to a network (User-Transferred Authorization Data Pattern)) and [Example A7: Transfer a session](#Example A7: Transfer a session (User-Transferred Authorization Data Pattern)).

### Request Initiation Verification
The user MAY be asked to verify if they initiated an authentication or authorization request by sending a one-time password (OTP) or PIN to the user's Authorization Device and asking them to enter it on the Initiating Device to confirm the request. If the request was initiated without the users' consent, they would receive an OTP or PIN out of context which may raise suspicion for the user. In addition, they would not have information on where to enter the OTP or PIN. The user experience on the Authorization Device MAY reinforce the risk of receiving an out-of-context OTP or PIN and provide information to the user on how to report an unauthorized authentication or authorization request.

**Limitations:** The additional verification step may reduce the overall usability of the system as it is one more thing users need to do right. Attackers may combine traditional phishing attacks and target users who respond to those messages with an interactive attack that sets the expectation with the user that they will have to provide the OTP or PIN, in addition to granting authorization for the request.

## Request Binding with Out-of-Band Data
In the User-Transferred Session Data Pattern, users MAY enter out-of-band information on the Initiating Device to start the authorization process. The out-of-band data entered by the user MAY then be included in the QR code which is displayed on the Initiating Device. When the QR code is scanned by the Authorizing Device, the out-of-band data is verified by the user or by the Authorizing Device. The out-of-ban data could be any attribute that the user or Authorizing Device can retrieve during the authorization process. Examples inlcude a serial number, one-time password or PIN, location or any other data that the user or the Authorizing Device can recall or retrieve during the authorization process ([@MPRCS2020], [@PCRSM2023]).

**Limitations:** A sophistacted attacker may include an additional step in their attack where they create a phishing attack that gathers the out-of-band data from the user before initiating the authorisation request. The additional step could also have a negative impact on the usability level of the solution.

### Practical Mitigation Summary
The practical mitigations described in this section can prevent the attacks from being initiated, disrupt attacks once they start or reduce the impact or remediate an attack if it succeeds. When combining one or more of these mitigations the overall security profile of a cross-device flow improves significantly. The following table provides a summary view of these mitigations:


|        Mitigation                    | Prevent | Disrupt | Recover |
|:-------------------------------------|:-------:|:-------:|:-------:|
|Establish Proximity                   |    X    |    X    |         |
|Short Lived/Timebound Codes           |         |    X    |         |
|One-Time or Limited Use Codes         |         |    X    |         |
|Unique Codes                          |         |    X    |         |
|Content Filtering                     |         |    X    |         |
|Detect and remediate                  |         |         |    X    |
|Trusted Devices                       |    X    |         |         |
|Trusted Networks                      |    X    |         |         |
|Limited Scopes                        |         |         |    X    |
|Short Lived Tokens                    |         |         |    X    |
|Rate Limits                           |    X    |    X    |         |
|Sender-Constrained Tokens             |         |         |    X    |
|User Education                        |    X    |         |         |
|User Experience                       |    X    |         |         |
|Authenticated flow                    |    X    |         |         |
|Request Initiation Verification       |         |    X    |         |
|Request Binding with Out-of-Band Data |         |    X    |         |
Table: Practical Mitigation Summary

## Protocol Selection
Some cross-device protocols are more susceptible to the exploits described in this document than others. In this section we will compare three different cross-device protocols in terms of their susceptibility to exploits focused on the unauthenticated channel, the prerequisites to implement and deploy them, along with guidance on when it is appropriate to use them.

### IETF OAuth 2.0 Device Authorization Grant [@RFC8628]:
#### Description
A standard to enable authorization on devices with constrained input capabilities (smart TVs, printers, kiosks). In this protocol, the user code or QR code is displayed or made available on the Initiating Device (smart TV) and entered on a second device (e.g., a mobile phone).

#### Susceptibility
There are several reports in the public domain outlining how the unauthenticated channel may be exploited to execute a Cross-Device Consent Phishing attack ([@Exploit1], [@Exploit2], [@Exploit3], [@Exploit4], [@Exploit5], [@Exploit6]).

#### Device Capabilities
There are no assumptions in the protocol about underlying capabilities of the device, making it a "least common denominator" protocol that is expected to work on the broadest set of devices and environments.

#### Mitigations
In addition to the security considerations section in the standard, it is RECOMMENDED that one or more of the mitigations outlined in this document be considered, especially mitigations that can help establish proximity or prevent attackers from obtaining QR or user codes.

#### When to use
Only use this protocol if other cross-device protocols are not viable due to device or system constraints. Avoid using if the protected resources are sensitive, high value, or business critical. Always deploy additional mitigations like proximity or only allow with pre-registered devices. Do not use for same-device scenarios (e.g. if the Initiating Device and Authorization Device is the same device).

### OpenID Foundation Client Initiated Back-Channel Authentication (CIBA):
#### Description
Client Initiated Back-Channel Authentication (CIBA) [@CIBA]: A standard developed in the OpenID Foundation that allows a device or service (e.g., a personal computer, Smart TV, Kiosk) to request the OpenID Provider to initiate an authentication flow if it knows a valid identifier for the user. The user completes the authentication flow using a second device (e.g., a mobile phone). In this flow the user does not scan a QR code or obtain a user code from the Initiating Device, but is instead contacted by the OpenID Provider to complete the authentication using a push notification, e-mail, text message or any other suitable mechanism.

#### Susceptibility
Less susceptible to unauthenticated channel attacks, but still vulnerable to attackers who know or can guess the user identifier and initiate an attack as described in [Example B4: Illicit Transaction Authorization](#Example B4: Illicit Transaction Authorization (Backchannel-Transferred Session Pattern)).

#### Device Capabilities
There is no requirement on the Initiating Device to support specific hardware. The Authorization Device must be registered/associated with the user and it must be possible for the Authorization Server to trigger an authorization on this device.

#### Mitigations
In addition to the security considerations section in the standard, it is RECOMMENDED that one or more of the mitigations outlined in this document be considered, especially mitigations that can help establish proximity or prevent attackers from initiating authorization requests.

#### When to Use
Use CIBA instead of Device Authorization Grant if it is possible for the Initiating Device to obtain a user identifier on the Initiating Device (e.g., through an input or selection mechanism) and if the Authorization Server can trigger an authorization on the Authorization Device. Do not use for same-device scenarios (e.g. if the Initiating Device and Authorization Device is the same device).

### FIDO2/WebAuthn
#### Description
FIDO2/WebAuthn is a stack of standards developed in the FIDO Alliance and W3C respectively which allow for origin-bound, phishing-resistant user authentication using asymmetric cryptography that can be invoked from a web browser or native client. Version 2.2 of the FIDO Client to Authenticator Protocol (CTAP) supports a new cross-device authentication protocol, called "hybrid", which enables an external device, such as a phone or tablet, to be used as a roaming authenticator for signing into the primary device, such as a personal computer. This is commonly called FIDO Cross-Device Authentication (CDA).

When a user wants to authenticate using their mobile device (authenticator) for the first time, they need to link their authenticator to their main device. This is done using a scan of a QR code. When the authenticator scans the QR code, the device sends an encrypted BLE advertisement containing keying material and a tunnel ID. The main device and authenticator both establish connections to the web service, and the normal CTAP protocol exchange occurs.

If the user chooses to keep their authenticator linked with the main device, the QR code link step is not necessary for subsequent use. The user will receive a push notification on the authenticator.

#### Susceptibility
The Cross-Device Authentication flow proves proximity by leveraging BLE advertisements for service establishment, significantly reducing the susceptibility to any of the exploits described in Examples 1-6.

#### Device Capabilities
Both the Initiating Device and the authenticator require BLE support. The Initiating Device must support both FIDO2/WebAuthn, specifically CTAP 2.2 with hybrid transport. The mobile phone must support CTAP 2.2+ to be used as a cross-device authenticator.

#### Mitigations
FIDO Cross-Device Authentication (CDA) establishes proximity through the use of BLE, reducing the need for additional mitigations. An implementer MAY still choose to implement additional mitigation as described in this document.

#### When to Use
FIDO2/WebAuthn SHOULD be used for cross-device authentication scenarios whenever the devices are capable of doing so. It MAY be used as an authentication method with the Authorization Code Grant [@RFC6749] and PKCE [@RFC7663], to grant authorization to an Initiating Device (e.g., Smart TV or interactive whiteboard) using a mobile phone as the authenticating device. This combination of FIDO2/WebAuthn and Authorization Code Flow with PKCE enables cross device authorization flows, without the risks posed by the Device Authorization Grant [@RFC8628].

### Protocol Selection Summary
The FIDO Cross-Device Authentication (CDA) flow provides the best protection against attacks on the unauthenticated channel for cross device flows. It can be combined with OAuth 2.0 and OpenID Connect protocols for standards-based authorization and authentication flows. If FIDO2/WebAuthn support is not available, Client Initiated Backchannel Authentication (CIBA) provides an alternative, provided that there is a channel through which the authorization server can contact the end user. Examples of such a channel include device push notifications, e-mail or text messages which the user can access from their device. If CIBA is used, additional mitigations to enforce proximity and initiate transactions from trusted devices or trusted networks SHOULD be considered. The OAuth 2.0 Device Authorization Grant provides the most flexibility and has the lowest requirements on devices used, but it is RECOMMENDED that it is only used when additional mitigations are deployed to prevent attacks that exploit the unauthenticated channel between devices.


## Foundational Pillars
Experience with web authorization and authentication protocols such as OAuth and OpenID Connect has shown that securing these protocols can be hard. The major reason for this is that the landscape in which they are operating - the web infrastructure with browsers, servers, and the underlying network - is complex, diverse, and ever-evolving.

As is the case with other kinds of protocols, it can be easy to overlook vulnerabilities in this environment. One way to reduce the chances of hidden security problems is to use mathematical-logical models to describe the protocols, their environments and their security goals, and then use these models to try to prove security. This approach is what is usually subsumed as "formal security analysis".

There are two major strengths of formal analysis: First, finding new vulnerabilities does not require creativity - i.e., new classes of attacks can be uncovered even if no one thought of these attacks before. In a faithful model, vulnerabilities become clear during the proof process or even earlier. Second, formal analysis can exclude the existence of any attacks within the boundaries of the model (e.g., the protocol layers modeled, the level of detail and functionalities covered, the assumed attacker capabilities, and the formalized security goals). As a downside, there is usually a gap between the model (which necessarily abstracts away from details) and implementations. In other words, implementations can introduce flaws where the model does not have any. Nonetheless, for protocol standards, formal analysis can help to ensure that the specification is secure when implemented correctly.

There are various different approaches to formal security analysis and each brings its own strengths and weaknesses. For example, models differ in the level of detail in which they can capture a protocol (granularity, expressiveness), in the kind of statements they can produce, and whether the proofs can be assisted by tools or have to be performed manually. One of the most successfully used approaches is the so-called Web Infrastructure Model (WIM), a model specifically designed for the analysis of web authentication and authorization protocols. While it is a manual (pen-and-paper) model, it captures details of browsers and web interactions in unprecedented detail. Using the WIM, previously unknown flaws in OAuth, OpenID Connect, and FAPI were discovered.

To ensure secure cross-device interactions, a formal analysis using the WIM therefore seems to be in order. Such an analysis should comprise a generic model for cross-device flows, potentially including different kinds of interactions. The aim of the analysis would be to evaluate the effectiveness of selected mitigation strategies. To the best of our knowledge, this would be the first study of this kind.

# Conclusion
Cross-device flows enable authorization on devices with limited input capabilities, allow for secure authentication when using public or shared devices, provide a path towards multi-factor authentication and, provide the convenience of a single, portable credential store.

The popularity of cross-device flows attracted the attention of attackers that exploit the unauthenticated channel between the Initiating Device and Authorization Device using techniques commonly used in phishing attacks. These Cross-Device Consent Phishing (CDCP) attacks allow attackers to obtain access and refresh tokens, rather than authentication credentials, resulting in access to resources even if the user used multi-factor authentication.

To address these attacks, we propose a three pronged approach that includes the deployment of practical mitigations to safeguard protocols that are already deployed, provide guidance on when to use different protocols, including protocols that are not susceptible to these attacks, and the introduction of formal methods to evaluate the impact of mitigations and find additional issues.

# Contributors
The authors would like to thank Tim Cappalli, Nick Ludwig, Adrian Frei, Nikhil Reddy Boreddy, Bjorn Hjelm, Joseph Heenan, Brian Campbell, Damien Bowden, Kristina Yasuda, Tim Würtele, Karsten Meyer zu Selhausen, Maryam Mehrnezhad and others (please let us know, if you've been mistakenly omitted) for their valuable input, feedback and general support of this work.

{backmatter}

# Document History

   [[ To be removed from the final specification ]]


   -latest
   * Introduced normative SHOULD, RECOMMENDED and MAY when applied to actions the Authorization Server, Resource Server or Client may implement.
   * Added User Education as a standalone mitigation.
   * Added Maryam Mehrnezhad to the contributors list.

   -02

   * Fixed typos and grammar edits
   * Capitalised Initiating Device and Authorization Device
   * Introduced Cross-Device Consent Phishing as a label for the types of attacks described in this document.
   * Updated labels for different types of flows (User-Transferred Session Data Pattern, Backchannel-Transferred Session Pattern, User-Transferred Authorization Data Pattern)
   * Adopted consistent use of hyphenation in using "cross-device"
   * Consistent use of "Authorization Device"
   * Update Reference to Secure Signals Framework to reflect name change from Secure Signals and Events
   * Described difference between proximity enforced and proximity-less cross-device flows
   * General editorial pass

   -01

   *  Added additional diagrams and descriptions to distinguish between different cross-device flow patterns.
   *  Added short description on limitations of each mitigation.
   *  Added acknowledgement of additional contributors.
   *  Fixed document history format.

   -00 (Working Group Draft)

   *  Initial WG revision (content unchanged from draft-kasselman-cross-device-security-03)

   -03 draft-kasselman-cross-device-security

   *  Minor edits and typos

   -02 draft-kasselman-cross-device-security

   *  Minor edits and typos
   *  Upload as draft-ietf-oauth-cross-device-security-best-practice-02

   -01 draft-kasselman-cross-device-security

   *  Updated draft based on feedback from version circulated to OAuth working group
   *  Upload as draft-ietf-oauth-cross-device-security-best-practice-01

   -00 draft-kasselman-cross-device-security

   *  Initial draft adopted from document circulated to the OAuth Security Workshop Slack Channel
   *  Upload as draft-ietf-oauth-cross-device-security-best-practice-00

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

<reference anchor="CIBA" target="https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html">
  <front>
    <title>OpenID Connect Client-Initiated Backchannel Authentication Flow - Core 1.0</title>
    <author initials="G." surname="Fernandez" fullname="Gonzalo Fernandez Rodriguez">
      <organization>Telefonica</organization>
    </author>
    <author initials="F." surname="Walter" fullname="Florian Walter">
      <organization>Deutsche Telekom AG</organization>
    </author>
    <author initials="A" surname="Nennker" fullname="Axel Nennker">
      <organization>Deutsche Telekom AG</organization>
    </author>
    <author initials="D." surname="Tonge" fullname="Dave Tonge">
      <organization>Moneyhub</organization>
    </author>
    <author initials="B." surname="Campbell" fullname="Brian Campbell">
      <organization>Ping Identity</organization>
    </author>
    <date year="2021" month="September"/>
  </front>
</reference>

<reference anchor="Exploit1" target="https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html">
  <front>
    <title>The Art of the Device Code Phish</title>
    <author initials="B." surname="Cooke" fullname="Bobby Cooke">
      <organization></organization>
    </author>
    <date year="2021" month="July"/>
  </front>
</reference>

<reference anchor="Exploit2" target="https://www.optiv.com/insights/source-zero/blog/microsoft-365-oauth-device-code-flow-and-phishing">
  <front>
    <title>Microsoft 365 OAuth Device Code Flow and Phishing</title>
    <author>
      <organization></organization>
    </author>
    <date year="2021" month="August"/>
  </front>
</reference>

<reference anchor="Exploit3" target="https://o365blog.com/post/phishing/#new-phishing-technique-device-code-authentication">
  <front>
    <title>Introducing a new phishing technique for compromising Office 365 accounts</title>
    <author initials="N." surname="Syynimaa " fullname="Nestori Syynimaa">
      <organization></organization>
    </author>
    <date year="2020" month="October"/>
  </front>
</reference>

<reference anchor="Exploit4" target="https://www.youtube.com/watch?v=9slRYvpKHp4">
  <front>
    <title>New Phishing Attacks Exploiting OAuth Authentication Flows (DEFCON 29)</title>
    <author initials="J." surname="Hwong " fullname="Jenko Hwong">
      <organization></organization>
    </author>
    <date year="2021" month="August"/>
  </front>
</reference>

<reference anchor="Exploit5" target="https://www.secureworks.com/blog/oauths-device-code-flow-abused-in-phishing-attacks">
  <front>
    <title>OAuth's Device Code Flow Abused in Phishing Attacks</title>
    <author>
      <organization></organization>
    </author>
    <date year="2021" month="August"/>
  </front>
</reference>

<reference anchor="Exploit6" target="https://www.helpnetsecurity.com/2022/08/11/squarephish-video/">
  <front>
    <title>SquarePhish: Advanced phishing tool combines QR codes and OAuth 2.0 device code flow</title>
    <author>
      <organization></organization>
    </author>
    <date year="2022" month="August"/>
  </front>
</reference>

<reference anchor="NYC.Bike" target="https://nypost.com/2021/08/07/citi-bikes-being-swiped-by-joyriding-scammers-who-have-cracked-the-qr-code/">
  <front>
    <title>Citi Bikes being swiped by joyriding scammers who have cracked the QR code</title>
    <author initials="K.J." surname="Byrne" fullname="Kerry J. Byrne">
      <organization></organization>
    </author>
    <date year="2021" month="August"/>
  </front>
</reference>

<reference anchor="SSF" target="https://openid.net/specs/openid-sse-framework-1_0-01.html">
  <front>
    <title>OpenID Shared Signals and Events Framework Specification 1.0</title>
    <author initials="A." surname="Tulshibagwale" fullname="Atul Tulshibagwale">
      <organization>Google</organization>
    </author>
    <author initials="T." surname="Cappalli" fullname="Tim Cappalli">
      <organization>Microsoft</organization>
    </author>
    <author initials="M." surname="Scurtescu" fullname="Marius Scurtescu">
      <organization>Coinbase</organization>
    </author>
    <author initials="A." surname="Backman" fullname="Annabelle Backman">
      <organization>Amazon</organization>
    </author>
    <author initials="J." surname="Bradley" fullname="John Bradley">
      <organization>Yubico</organization>
    </author>
    <date year="2021" month="June"/>
  </front>
</reference>

<reference anchor="CAEP" target="https://openid.net/specs/openid-caep-specification-1_0-01.html">
  <front>
    <title>OpenID Continuous Access Evaluation Profile 1.0 - draft 01</title>
    <author initials="A." surname="Tulshibagwale" fullname="Atul Tulshibagwale">
      <organization>Google</organization>
    </author>
    <author initials="T." surname="Cappalli" fullname="Tim Cappalli">
      <organization>Microsoft</organization>
    </author>
    <date year="2021" month="June"/>
  </front>
</reference>

<reference anchor="OpenID.SIOPV2" target="https://bitbucket.org/openid/connect/src/master/openid-connect-self-issued-v2/openid-connect-self-issued-v2-1_0.md">
  <front>
    <title>Self-Issued OpenID Provider v2</title>
    <author initials="K." surname="Yasuda" fullname="Kristina Yasuda">
      <organization>Microsoft</organization>
    </author>
    <author initials="M." surname="Jones" fullname="Michael B. Jones">
      <organization>Microsoft</organization>
    </author>
    <author initials="T." surname="Lodderstedt" fullname="Torsten Lodderstedt">
      <organization>yes.com</organization>
    </author>
    <date year="2022" month="November"/>
  </front>
</reference>

<reference anchor="IEEE802154" target="https://standards.ieee.org/standard/802_15_4-2020.html">
  <front>
    <title>IEEE Std 802.15.4-2020: IEEE Standard for Low-Rate Wireless Networks</title>
    <author fullname="Institute of Electrical and Electronics Engineers"/>
    <date year="2020"/>
  </front>
  <seriesInfo name="IEEE" value="802.15.4-2020"/>
  <annotation>This standard defines the physical layer and media access control for low-rate wireless personal area networks (LR-WPANs) and is maintained by the IEEE 802.15 working group.</annotation>
</reference>

<reference anchor="Baki2023" target="https://doi.org/10.1109/TDSC.2022.3151103">
  <front>
    <title>Sixteen Years of Phishing User Studies: What Have We Learned?</title>
    <author initials="S." surname="Baki">
      <organization>IEEE Transactions on Dependable and Secure Computing</organization>
    </author>
    <author initials="R. M." surname="Verma">
      <organization>IEEE Transactions on Dependable and Secure Computing</organization>
    </author>
    <date year="2023"/>
  </front>
  <seriesInfo name="Volume" value="20"/>
  <seriesInfo name="Number" value="2"/>
  <seriesInfo name="Pages" value="1200-1212"/>
  <format type="doi">10.1109/TDSC.2022.3151103</format>
</reference>

<reference anchor="MPRCS2020" target="https://doi.org/10.1145/3374664.3375727">
  <front>
    <title>The Good, the Bad and the (Not So) Ugly of Out-of-Band Authentication with eID Cards and Push Notifications: Design, Formal and Risk Analysis</title>
    <author initials="M." surname="Pernpruner" fullname="Marco Pernpruner"/>
    <author initials="R." surname="Carbone" fullname="Roberto Carbone"/>
    <author initials="S." surname="Ranise" fullname="Silvio Ranise"/>
    <author initials="G." surname="Sciarretta" fullname="Giada Sciarretta"/>
    <date year="2020"/>
  </front>
  <seriesInfo name="Proceedings of the Tenth ACM Conference on Data and Application Security and Privacy (CODASPY '20)" />
  <organization>Association for Computing Machinery</organization>
  <address>New York, NY, USA</address>
  <pages>223–234</pages>
</reference>

<reference anchor="PCRSM2023" target="https://doi.org/10.1109/TDSC.2023.3296210">
  <front>
    <title>An Automated Multi-Layered Methodology to Assist the Secure and Risk-Aware Design of Multi-Factor Authentication Protocols</title>
    <author initials="M." surname="Pernpruner" fullname="Marco Pernpruner"/>
    <author initials="R." surname="Carbone" fullname="Roberto Carbone"/>
    <author initials="G." surname="Sciarretta" fullname="Giada Sciarretta"/>
    <author initials="S." surname="Ranise" fullname="Silvio Ranise"/>
    <date year="2023"/>
  </front>
  <seriesInfo name="IEEE Transactions on Dependable and Secure Computing (TDSC)" />
  <organization>IEEE</organization>
</reference>
