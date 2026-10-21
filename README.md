# Noos Firewall (`noos-firewall`)

**Noos Firewall** (*Pare-feu*) est une interface graphique moderne et native de gestion du pare-feu **UFW** (*Uncomplicated Firewall*) pour **Arch Linux**, écrite intégralement en **Rust** avec **GTK4** et **Libadwaita**.

---

## Fonctionnalités Principales

- **Contrôle de l'état en temps réel (`ufw` & `systemctl`)** :
  - Interrupteur principal pour activer (`pkexec ufw --force enable`) ou désactiver (`pkexec ufw disable`) le pare-feu avec indicateur visuel clair (**Protégé (Actif)** / **Désactivé**) et affichage des politiques par défaut (*Entrée : Bloquée*, *Sortie : Autorisée*).
  - Gestion propre des annulations d'authentification Polkit (`pkexec`) sans blocage de l'interface.
- **Gestion des Ports & Règles numérotées (`ufw status numbered`)** :
  - Affichage structuré des règles actives avec numéro de règle (`#1`, `#2`…), port/plage, nom du service réseau associé (ex. *SSH*, *KDE Connect*, *HTTP/HTTPS*, *LocalSend*), protocole (`TCP`, `UDP`, `Tous`), direction (`IN`, `OUT`) et action (`ALLOW`, `DENY`).
  - Ajout de règles via une boîte de dialogue modale Libadwaita avec validation stricte anti-injection (`1..=65535` ou plages `debut:fin`) et prévisualisation de la commande exécutée.
  - Suppression de règles en un clic avec confirmation (`pkexec ufw --force delete <numero>`).
- **Journaux de blocage enrichis et pédagogiques (`journalctl -k -g "UFW BLOCK"`)** :
  - Résolution automatique du **nom d'hôte de la machine source** (mDNS `.local`, `/etc/hosts`, `systemd-resolved`, DNS inverse), détection automatique de la **Box / Routeur** local et identification du **fabricant (adresse MAC / OUI)**.
  - Identification claire du **service ou de l'application ciblée** (mDNS/Avahi, KDE Connect, LocalSend, Samba/SMB, UPnP/DLNA, SSH, Multicast IGMP, Ping ICMP…) et distinction entre le bruit de découverte local (*Réseau local*, *Box / Routeur*, *VM*) et les tentatives provenant d'*Internet*.
  - Lignes dépliables (`AdwExpanderRow`) offrant une explication en français clair et un bouton **« Autoriser Port/Protocole »** pour débloquer une application légitime en un clic.
  - Barre de recherche instantanée par nom d'appareil, adresse IP, service, port ou protocole.

---

## Installation

### Depuis l'AUR (Arch Linux)

Avec `yay` :
```bash
yay -S noos-firewall
```

Avec `paru` :
```bash
paru -S noos-firewall
```

Manuellement avec `makepkg` :
```bash
git clone https://aur.archlinux.org/noos-firewall.git
cd noos-firewall
makepkg -si
```

### Compilation depuis les sources

#### Prérequis système (Arch Linux)
```bash
sudo pacman -S --needed rust cargo gtk4 libadwaita ufw polkit git
```

#### Compilation et exécution
```bash
git clone https://github.com/Chomiam/noos-firewall.git
cd noos-firewall
cargo build --release
./target/release/noos-firewall
```

---

## Licence

Distribué sous licence **GPL-3.0-or-later**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.
