export interface DemoEmail {
  id: string;
  name: string;
  category: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "SAFE";
  raw: string;
}

export const DEMO_EMAILS: DemoEmail[] = [
  {
    id: "phishing-ms365",
    name: "Credential Phishing (Microsoft 365 Alert)",
    category: "Credential Harvesting",
    severity: "CRITICAL",
    description: "Urgent account suspension lure, spoofed security headers, anchor text deception, and SPF/DKIM/DMARC failures.",
    raw: `From: "Microsoft 365 Security" <security-alerts@microsoft-security.example>
To: analyst@enterprise-defense.org
Subject: URGENT: Your Microsoft 365 account will be suspended within 24 hours
Date: Fri, 04 Sep 2026 09:14:22 +0000
Message-ID: <alert-20260904-8921@microsoft-security.example>
Reply-To: support-tickets@phish-evasion-node.top
Return-Path: <bounce@unauthorized-relays.com>
Authentication-Results: mx.enterprise-defense.org;
 dkim=fail (bad signature) header.d=microsoft-security.example;
 spf=fail (client-ip=203.0.113.195) smtp.mailfrom=bounce@unauthorized-relays.com;
 dmarc=fail action=quarantine header.from=microsoft-security.example
Received-SPF: Fail (mx.enterprise-defense.org: domain of bounce@unauthorized-relays.com does not designate 203.0.113.195 as permitted sender) client-ip=203.0.113.195;
Received: from mx.enterprise-defense.org (mx.enterprise-defense.org [198.51.100.88])
    by gateway.enterprise-defense.org with ESMTP id 82193
    for <analyst@enterprise-defense.org>; Fri, 04 Sep 2026 09:15:02 +0000
Received: from mail-node-42.suspicious-relay.net (mail-node-42.suspicious-relay.net [203.0.113.195])
    by mx.enterprise-defense.org with ESMTP id 59281
    for <analyst@enterprise-defense.org>; Fri, 04 Sep 2026 09:14:30 +0000
Received: from workstation-dynamic.example (workstation-dynamic.example [192.0.2.1])
    by mail-node-42.suspicious-relay.net with HTTP id 10928;
    Fri, 04 Sep 2026 09:14:22 +0000
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<body>
<div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px;">
    <h2 style="color: #d93025;">CRITICAL SECURITY ALERT: Account Suspension Notice</h2>
    <p>Dear Valued User,</p>
    <p>We detected multiple unauthorized login attempts to your corporate account from an unrecognized IP address in Moscow, Russia.</p>
    <p><b>Your account access has been temporarily locked to prevent data exfiltration.</b></p>
    <p>You must verify your identity and confirm your corporate password within <b>24 hours</b>, or your mailbox and all cloud documents will be permanently terminated.</p>
    <p style="margin: 25px 0;">
        <a href="http://secure-portal-update.top/auth/verify?session=98218&redirect=login" 
           style="background-color: #0078d4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; font-weight: bold;">
           Verify Account Password Immediately
        </a>
    </p>
    <p>Or copy the verification link: <a href="http://203.0.113.195/session/re-activate">https://account.microsoft.com/security/verify-identity</a></p>
</div>
</body>
</html>`,
  },
  {
    id: "invoice-fraud",
    name: "Invoice Fraud (Wire Diversion)",
    category: "Financial Fraud",
    severity: "HIGH",
    description: "Altered wire remittance instructions, offshore settlement account, Bitcoin payment option, and suspicious .xyz domain.",
    raw: `From: "Accounts Payable Dept" <billing@supplies-logistics-corp.xyz>
To: finance@victim-enterprise.org
Subject: OVERDUE INVOICE #INV-884920 - Immediate Remittance Required
Date: Wed, 02 Sep 2026 11:30:15 +0000
Message-ID: <inv-884920@supplies-logistics-corp.xyz>
Reply-To: wire-collections@urgent-remittance-center.top
Return-Path: <bounce@unverified-relay.net>
Authentication-Results: mx.victim-enterprise.org;
 spf=softfail (client-ip=198.51.100.25) smtp.mailfrom=bounce@unverified-relay.net;
 dkim=none;
 dmarc=fail action=none header.from=supplies-logistics-corp.xyz
Received: from mx.victim-enterprise.org (mx.victim-enterprise.org [198.51.100.88])
    by gateway.victim-enterprise.org with ESMTP id 98124
    for <finance@victim-enterprise.org>; Wed, 02 Sep 2026 11:30:40 +0000
Received: from transit-node-09.hetzner-demo.de (transit-node-09.hetzner-demo.de [198.51.100.25])
    by mx.victim-enterprise.org with ESMTP id 12903;
    Wed, 02 Sep 2026 11:30:15 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Dear Finance Director,

Our records show that invoice #INV-884920 for $64,200.00 is currently 14 days overdue.

CRITICAL NOTICE: Due to our recent corporate banking transition, our previous bank account has been permanently closed.

Please update your remittance records immediately and execute the wire transfer to our new offshore settlement account:
- Beneficiary Bank: Global Commercial Trust Bank
- Account Name: Supplies Logistics Global Escrow Ltd
- Routing: GCTBUS33XXX
- Account: 9812-4091-8821
- Bitcoin Escrow Alternative: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT

Remit wire transfer confirmation within 24 hours to avoid litigation.
Download Certified Invoice: http://billing-settlement-portal.top/invoices/download?id=884920`,
  },
  {
    id: "ceo-impersonation",
    name: "Executive Impersonation (CEO BEC)",
    category: "Executive Impersonation",
    severity: "HIGH",
    description: "Free Gmail address impersonating corporate CEO, confidential urgency, requests gift card codes without phone calls.",
    raw: `From: "Sarah Jenkins (CEO)" <ceo.office.jenkins9821@gmail.com>
To: accounting-lead@victim-enterprise.org
Subject: Urgent Confidential Request - Are you at your desk?
Date: Tue, 01 Sep 2026 16:45:00 +0000
Message-ID: <ceo-urgent-msg-9102@gmail.com>
Reply-To: private-exec-task@freemail-secure.xyz
Return-Path: <ceo.office.jenkins9821@gmail.com>
Authentication-Results: mx.victim-enterprise.org;
 spf=pass (client-ip=192.0.2.1) smtp.mailfrom=ceo.office.jenkins9821@gmail.com;
 dkim=pass header.d=gmail.com;
 dmarc=fail action=none header.from=victim-enterprise.org
Received: from mail-relay.victim-enterprise.org (mail-relay.victim-enterprise.org [198.51.100.88])
    by gateway.victim-enterprise.org with ESMTP id 50192
    for <accounting-lead@victim-enterprise.org>; Tue, 01 Sep 2026 16:45:20 +0000
Received: from mail-io-f1.google.com (mail-io-f1.google.com [192.0.2.1])
    by mail-relay.victim-enterprise.org with ESMTPS id 20491;
    Tue, 01 Sep 2026 16:45:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hi,

Are you at your desk right now?

I am currently wrapped up in a confidential acquisition board meeting and cannot take incoming phone calls.

I need you to handle an urgent executive priority for our strategic clients today. We need 10 Apple digital gift cards of $250 each purchased immediately for our key account partners.

Please charge this to the department card and email me the card codes and PINs directly to this address.

Keep this discreet between us until we announce the transaction tomorrow morning.

Thanks,
Sarah Jenkins
Chief Executive Officer
Victim Enterprise Inc.`,
  },
  {
    id: "malware-delivery",
    name: "Malware Delivery (.pdf.exe Attachment)",
    category: "Attachment Threat",
    severity: "CRITICAL",
    description: "Double extension deceptive binary Customs_Declaration_Waybill.pdf.exe disguised as customs clearance form.",
    raw: `From: "Swift Freight Logistics" <dispatch@freight-tracker-node.net>
To: logistics-team@victim-enterprise.org
Subject: Delivery Failure: Waybill #US-882194 Documentation Attached
Date: Mon, 31 Aug 2026 08:22:10 +0000
Message-ID: <dispatch-882194@freight-tracker-node.net>
Reply-To: dispatch@freight-tracker-node.net
Return-Path: <bounce@untrusted-relay.top>
Authentication-Results: mx.victim-enterprise.org;
 spf=fail (client-ip=203.0.113.50);
 dkim=none;
 dmarc=fail header.from=freight-tracker-node.net
Received: from exit-node.bulletproof-host.nl (exit-node.bulletproof-host.nl [203.0.113.50])
    by mx.victim-enterprise.org with ESMTP id 10928;
    Mon, 31 Aug 2026 08:22:10 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_99182_Boundary"

------=_Part_99182_Boundary
Content-Type: text/plain; charset=UTF-8

Attention Receiving Agent,

Your air cargo parcel #US-882194 encountered a customs clearance exception at the distribution depot.

Attached is the mandatory customs clearance declaration and commercial bill of lading. Please extract and sign the document immediately to prevent parcel forfeiture.
------=_Part_99182_Boundary
Content-Type: application/octet-stream; name="Customs_Declaration_Waybill882194.pdf.exe"
Content-Disposition: attachment; filename="Customs_Declaration_Waybill882194.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAsAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4g
RE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAAOAADAgELAQAA
AAAAAAAAAAAAAAAAMAEAAAQAAAAAAAAA
------=_Part_99182_Boundary--`,
  },
  {
    id: "safe-meeting",
    name: "Safe Corporate Communication",
    category: "Benign Corporate",
    severity: "SAFE",
    description: "Authentic engineering meeting notice with passing SPF, DKIM, and DMARC alignment and clean internal links.",
    raw: `From: "Engineering Leadership" <engineering-updates@techcorp-defense.example>
To: engineering-all@techcorp-defense.example
Subject: Q3 Architecture Review & Infrastructure Migration Roadmap
Date: Thu, 03 Sep 2026 14:20:00 +0000
Message-ID: <eng-q3-2026-0903@techcorp-defense.example>
Reply-To: engineering-updates@techcorp-defense.example
Return-Path: <engineering-updates@techcorp-defense.example>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=techcorp-defense.example; s=selector1; t=1756910400; h=from:to:subject:date:message-id; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdF9ka2ltX3NpZ25hdHVyZQ==
Authentication-Results: mx.techcorp-defense.example;
 dkim=pass header.d=techcorp-defense.example;
 spf=pass (client-ip=198.51.100.88) smtp.mailfrom=engineering-updates@techcorp-defense.example;
 dmarc=pass header.from=techcorp-defense.example
Received: from corporate-mail.techcorp-defense.example (corporate-mail.techcorp-defense.example [198.51.100.88])
    by mx.techcorp-defense.example with ESMTPS id 44109
    for <engineering-all@techcorp-defense.example>; Thu, 03 Sep 2026 14:20:15 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Team,

Here is the finalized agenda for our Q3 Architecture Review taking place tomorrow at 10:00 AM UTC in the engineering auditorium and over our internal video bridge.

Key discussion items:
1. Microservices decoupling progress and latency metrics
2. Zero-trust network access (ZTNA) migration timeline
3. Automated canary deployments in production Kubernetes clusters

Please review the architectural RFC prior to the meeting:
https://techcorp-defense.example/internal/wiki/rfc-409

Best regards,
Engineering Operations
TechCorp Defense`,
  },
];
