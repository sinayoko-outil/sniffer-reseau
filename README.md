Documentation du Sniffer-Réseau Avancé 🛠️
1. Introduction 🚀

Ce programme est un sniffer réseau avancé qui permet de capturer et d'analyser le trafic réseau en temps réel. Grâce à une interface graphique conviviale réalisée avec Tkinter, il offre les fonctionnalités suivantes :

    Capture en temps réel : Interception des paquets circulant sur l'interface réseau choisie.
    Affichage détaillé : Pour chaque paquet, affichage de l'heure, de l'adresse source et destination, ainsi que des informations sur les ports (TCP/UDP) et les requêtes DNS.
    Log des activités : Enregistrement des données dans un fichier traffic_log.txt pour une analyse ultérieure.
    Statistiques en direct : Suivi du nombre total de paquets capturés et possibilité d'étendre le suivi à d'autres protocoles (HTTP, FTP, etc.).
    Extensibilité : Une base solide pour intégrer des fonctionnalités supplémentaires comme des filtres avancés, des visualisations graphiques ou des alertes en cas d'activité suspecte.

Cet outil est pensé pour les passionnés de cybersécurité et les développeurs qui veulent explorer le monde du sniffing et de l'analyse réseau avec un outil moderne et évolutif. 🔍
2. Installation 📦

Avant de pouvoir utiliser ce sniffer réseau, quelques dépendances doivent être installées :

    Python
    Assure-toi d'avoir Python 3.6 ou une version ultérieure installé sur ton système. Tu peux télécharger Python depuis python.org.

    Tkinter
    Tkinter est généralement inclus avec Python.
        Sous Linux, si Tkinter n'est pas présent, installe-le via ton gestionnaire de paquets :

    sudo apt-get install python3-tk

    Sous Windows et macOS, Tkinter est habituellement installé par défaut.

Scapy
Cette librairie est essentielle pour la capture et l'analyse des paquets.
Installe-la avec pip :

    pip install scapy

    Modules standards
    Les modules sys, time, logging, threading et datetime sont intégrés à Python et ne nécessitent aucune installation supplémentaire.

3. Utilisation de l'Outil 🏃‍♂️

Pour exécuter ce sniffer réseau, suis ces étapes simples :

    Lancement du programme
    Ouvre un terminal et navigue jusqu'au dossier contenant ton script. Puis, lance-le avec :

    python nom_du_script.py

    Interface Graphique
    Une fois le programme lancé, une fenêtre s'ouvrira avec les éléments suivants :
        Champ d'interface réseau : Choix de l'interface (par défaut eth0). Modifie-le si nécessaire.
        Bouton Démarrer : Clique pour lancer la capture des paquets.
        Bouton Arrêter : Permet de stopper le sniffing à tout moment.
        Zone de texte : Affiche en temps réel les logs des paquets capturés.
        Label de statistiques : Montre le nombre total de paquets capturés.

    Exécution et arrêt du sniffing
        Pour démarrer le sniffing, clique sur Démarrer. La capture commence alors et les paquets sont affichés en direct dans la zone de texte.
        Pour arrêter le sniffing, clique sur Arrêter. Le programme arrête alors la capture des paquets et met à jour l'interface en conséquence.

4. Justification des Critères et Logique de Détection 🧠

Le programme intègre plusieurs critères de détection pour offrir une analyse complète du trafic réseau :

    Analyse des paquets IP :
    Chaque paquet est vérifié pour la présence d'un en-tête IP afin d'extraire l'adresse source et destination. Cette étape est cruciale pour identifier les points de communication.

    Distinguer les protocoles TCP et UDP :
    En fonction de la présence d'un en-tête TCP ou UDP, le programme logue le port de destination correspondant. Cela permet d'identifier les types de services utilisés (ex. HTTP sur le port 80, DNS sur le port 53).

    Détection des requêtes DNS :
    En analysant les paquets DNS et en vérifiant que le flag qr est à 0 (indiquant une requête), le sniffer enregistre le nom de domaine recherché. Cette fonctionnalité aide à détecter des requêtes potentiellement suspectes ou malveillantes.

    Suivi des statistiques :
    Un dictionnaire global STATS permet de compter en temps réel le nombre total de paquets ainsi que les occurrences de certains types de trafic (HTTP, DNS, FTP, etc.). Cela pose les bases pour une future extension vers des analyses plus poussées (alertes, visualisations, etc.).

    Utilisation de Scapy :
    Scapy offre une flexibilité remarquable dans la manipulation des paquets, permettant de capturer et de traiter des paquets de manière efficace. Le choix de cette librairie est motivé par sa puissance et sa popularité dans le domaine de la cybersécurité.

L'ensemble de ces critères permet de détecter, enregistrer et analyser efficacement le trafic réseau, en offrant une vision détaillée de l'activité sur le réseau. C'est un excellent point de départ pour quiconque souhaite approfondir ses compétences en analyse réseau et en cybersécurité. 🚀
5. Exemples de Sortie 📜

Voici quelques extraits typiques que vous pourriez trouver dans le fichier traffic_log.txt :

    Exemple d'un paquet TCP :

[12:34:56] 192.168.1.100 -> 93.184.216.34 TCP Port: 80

Exemple d'un paquet UDP :

[12:35:01] 192.168.1.100 -> 8.8.8.8 UDP Port: 53

Exemple d'une requête DNS :

    [12:35:05] 192.168.1.100 -> 8.8.8.8 DNS Request: example.com

Ces exemples illustrent comment le sniffer enregistre l'heure, les adresses IP et les détails spécifiques des paquets, facilitant ainsi l'analyse des communications sur le réseau.

En résumé, ce sniffer-réseau avancé est une solution puissante et flexible pour capturer et analyser le trafic réseau. Avec son interface graphique intuitive et sa logique de détection robuste, il est idéal pour les amateurs de cybersécurité qui souhaitent explorer et surveiller l'activité réseau de manière ludique et efficace. Alors, prêt à plonger dans le futur de l'analyse réseau ? Bonne exploration et bon sniffing ! 🚀😄