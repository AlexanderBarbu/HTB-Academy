# Introduction
## Penetration Testing Stages & Situations

- **Engagement Variability**: Scope, results, environment differ per client.  
- **Internal Pentest**: Usually given internal host with internet → need VPS for tools/resources.  
- **Remote Testing**:  
  - Ship preinstalled device.  
  - Provide VM calling back to infra (OpenVPN).  
  - Client-hosted image → SSH + customization.  
  - VPN access directly → use local Linux & Windows VMs.  
- **On-Site Testing**:  
  - Bring up-to-date Linux & Windows VMs.  
  - Linux → tool support.  
  - Windows → easier AD enumeration.  
- **Key Principle**: Be versatile & adaptable, guide client to optimal solution.  
- **Day 1 Prep**: Fully tooled & structured VMs → minimize wasted time.  

---

## Setup & Efficiency

- **Structured Setup**: Organized, prebaked, reproducible → faster engagements.  
- **Pitfalls**:  
  - Too many tools → bloat, slowdowns.  
  - Info overload → 50 different “best setups”.  
  - Migration challenges when switching environments.  
- **Best Practice**:  
  - Build **personal, minimal, adaptable environment**.  
  - Know it inside out, configure & adapt independently.  
- **Efficiency**:  
  - Avoid searching for dependencies mid-engagement.  
  - Prepared environments = focus on assessment, not setup.
 