# Exercice Mission : Administrer un Système Linux 


Vous avez été désigné comme étant administrateur système junior dans une petite entreprise de cybersécurité. Vous avez une liste de tâches à réaliser ci-dessous, et des notes à prendre pour indiquer les commandes entrées pour parvenir à vos buts.

## Liste des tâches :
### Gestion des Fichiers et Dossiers : 

- Créez un répertoire appelé "documents_entreprise" dans le répertoire /root.
    - `sudo mkdir /root/documents_entreprise`
- Dans ce dossier "documents_entreprise", créez deux sous-répertoires, l'un appelé "rapports" et l'autre "factures".
    - `sudo mkdir /root/documents_entreprise/rapports /root/documents_entreprise/factures`
- Créez un fichier texte appelé "" dans le répertoire personnel de l'utilisateur "utilisateur".
    - `touch ~/ma_mission.txt`
- Donnez-lui du texte comme "voici ma mission" (ou copiez/collez cet exercice dedans).
    - `echo "voici ma mission" > ~/ma_mission.txt`

### Gestion des Permissions: 

- Assurez vous que seul l'utilisateur "root" soit propriétaire du fichier "ma_mission.txt".
    - ```
        utilisateur@cyberini1:~$ sudo chown root: ~/ma_mission.txt
        [sudo] password for utilisateur:
        utilisateur@cyberini1:~$ ll ~/ma_mission.txt
        -rw-r--r-- 1 root root 17 Feb 17 14:03 /home/utilisateur/ma_mission.txt
    ```
- Donnez les droits de lecture, d'écriture et d'exécution à ce fichier pour l'utilisateur root. 
- Retirez tous les autres droits aux autres membres et au groupe.
- Créez un script shell qui dit "Bonjour" et exécutez-le.

### Gestion des Processus : 

- Récupérez le load average des 15 dernières minutes. 
- Ouvrez l'éditeur de texte "nano" en arrière plan. 
- Trouvez l'identifiant de processus (PID) de "nano". 
- Eliminez le processus nano avec la commande "kill" (trouvez la bonne option).

### Gestion Réseau : 

- Trouvez le fichier "resolv.conf". 
- Trouvez l'adresse IP du serveur DNS ("nameserver"). 
- Trouvez l'adresse IP du site cyberini.com. 
- Récupérez le code source de example.net.

### Gestion Système : 

- Mettez à jour la liste des paquets et vérifiez que "nano" soit à jour.
- Trouvez combien de pourcentage d'espace libre il reste sur le disque. 
- Trouvez la version du noyau Linux. 
- Récupérez la valeur de la variable PATH.
