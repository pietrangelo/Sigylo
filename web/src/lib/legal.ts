// Terms of service and privacy notice of the hosted service at sigylo.net, in
// the same five languages as the interface. Plain text only: the page renders
// every string as text, never as HTML. The Apache License 2.0 covers the
// source code; these texts cover only the service run at sigylo.net.

import type { Language } from './i18n';

/** Who runs sigylo.net. The owner fills these in; a test refuses to ship them empty. */
export const operator = {
  name: 'Pietrangelo Masala',
  email: 'privacy@sigylo.net',
} as const;

/** Date of the last change to any of these texts (ISO 8601). */
export const LEGAL_UPDATED = '2026-10-17';

export interface LegalSection {
  heading: string;
  body: readonly string[];
}

export interface LegalDocument {
  title: string;
  sections: readonly LegalSection[];
}

export interface LegalTexts {
  terms: LegalDocument;
  privacy: LegalDocument;
}

const { name, email } = operator;

const it: LegalTexts = {
  terms: {
    title: `Termini di servizio`,
    sections: [
      {
        heading: `Chi offre il servizio`,
        body: [
          `Sigylo, all'indirizzo sigylo.net, è un servizio gratuito offerto da ${name} (Italia), contattabile a ${email}. Usando il servizio accetti questi termini. Se non li accetti, non usarlo.`,
        ],
      },
      {
        heading: `Come funziona e cosa non possiamo fare`,
        body: [
          `Il segreto viene cifrato sul tuo dispositivo prima di partire. Noi custodiamo soltanto dati illeggibili: la chiave sta nel link, che non arriva mai ai nostri server.`,
          `Per questo non possiamo leggere, recuperare o ricostruire un segreto. Se perdi il link, il segreto è perso. Chiunque abbia il link può aprirlo: condividilo solo con chi deve riceverlo e, per i dati più delicati, aggiungi una passphrase inviata per un altro canale.`,
          `Un segreto viene distrutto alla prima lettura o alla scadenza che hai scelto, al massimo dopo 7 giorni. Nella modalità richiesta non possiamo sapere chi ha sigillato la risposta.`,
        ],
      },
      {
        heading: `Uso consentito`,
        body: [
          `Puoi usare Sigylo solo per scopi leciti. È vietato usarlo per diffondere contenuti illegali, malware o materiale di phishing, per violare diritti altrui o per molestare qualcuno.`,
          `È vietato attaccare il servizio, sovraccaricarlo, aggirarne i limiti di frequenza o tentare di accedere a dati altrui. Possiamo limitare o bloccare l'accesso a chi viola queste regole.`,
        ],
      },
      {
        heading: `Segnalazioni e autorità`,
        body: [
          `Il punto di contatto unico per utenti e autorità, ai sensi del Regolamento (UE) 2022/2065 sui servizi digitali, è ${email}, in italiano o in inglese.`,
          `Poiché non vediamo i contenuti, possiamo intervenire solo su un link preciso che ci viene segnalato: in quel caso possiamo distruggere il segreto a cui rimanda.`,
        ],
      },
      {
        heading: `Servizio gratuito, senza garanzie`,
        body: [
          `Il servizio è offerto gratuitamente, così com'è e secondo disponibilità. Possiamo modificarlo, sospenderlo o chiuderlo in qualsiasi momento. Non usare Sigylo come unica copia di un dato che non puoi permetterti di perdere.`,
        ],
      },
      {
        heading: `Responsabilità`,
        body: [
          `Nei limiti consentiti dalla legge, non rispondiamo di danni indiretti, perdita di dati o uso dei link da parte di chi li riceve. Restano ferme la responsabilità per dolo o colpa grave (art. 1229 del codice civile) e i diritti che la legge riconosce ai consumatori e che non si possono escludere.`,
        ],
      },
      {
        heading: `Codice aperto e Apache License 2.0`,
        body: [
          `Il codice sorgente di Sigylo è distribuito con la Apache License 2.0. La licenza regola la copia, la modifica e la redistribuzione del codice, comprese la sua esclusione di garanzia (sezione 7) e la limitazione di responsabilità (sezione 8). Questi termini regolano invece solo l'uso del servizio su sigylo.net: chi esegue una propria copia del codice segue la licenza, non questi termini.`,
          `La licenza non concede diritti sui marchi (sezione 6): il nome Sigylo e il suo logo identificano questo servizio, e una versione modificata deve usare un altro nome. I componenti di terze parti restano soggetti alle proprie licenze; le attribuzioni sono nel file NOTICE del codice.`,
        ],
      },
      {
        heading: `Modifiche e legge applicabile`,
        body: [
          `Possiamo aggiornare questi termini; la data dell'ultimo aggiornamento è indicata in cima. Si applica la legge italiana. Se sei un consumatore restano ferme le tutele inderogabili del tuo Paese e il foro del tuo luogo di residenza. In caso di differenze tra le traduzioni prevale il testo italiano.`,
        ],
      },
    ],
  },
  privacy: {
    title: `Informativa sulla privacy`,
    sections: [
      {
        heading: `Titolare del trattamento`,
        body: [
          `${name} (Italia), ${email}. Questa informativa è resa ai sensi degli articoli 13 e 14 del Regolamento (UE) 2016/679 (GDPR).`,
        ],
      },
      {
        heading: `In breve`,
        body: [
          `Account facoltativi e senza email, nessun cookie, nessun tracciamento, nessuna analisi statistica. Non possiamo leggere ciò che sigilli: viene cifrato sul tuo dispositivo e la chiave non arriva mai ai nostri server.`,
        ],
      },
      {
        heading: `Cosa conserviamo`,
        body: [
          `Per ogni segreto: la busta cifrata, la scadenza, la regola di distruzione e l'impronta SHA-256 del codice di revoca. Per ogni richiesta: la chiave pubblica di chi la crea e, se arriva, la risposta cifrata. Per un file, in più: i suoi pezzi cifrati (su Cloudflare R2, nell'Unione europea, sotto nomi casuali), quanti sono e, dopo l'apertura, l'impronta SHA-256 del codice che li consegna solo a chi l'ha aperto.`,
          `Niente altro: né orario di creazione, né indirizzo IP, né identità. Anche se un segreto contiene dati personali, per noi resta illeggibile.`,
        ],
      },
      {
        heading: `Account facoltativi`,
        body: [
          `Se crei un account conserviamo: un hash con chiave del tuo nome utente (non il nome), il record di registrazione OPAQUE (la tua password non ci arriva mai, nemmeno come hash) e il tuo portachiavi, cifrato sul tuo dispositivo con una chiave che non vediamo mai, con un contatore delle sue modifiche. Il portachiavi contiene i codici per distruggere i segreti che hai sigillato da connesso, non i link per aprirli.`,
          `Mentre sei connesso conserviamo l'impronta SHA-256 del codice di sessione e la sua scadenza, al massimo 12 ore; durante un accesso, per cinque minuti, lo stato del protocollo. L'account resta finché non lo elimini dalla pagina dell'account, che cancella tutto in una volta.`,
          ],
        },
        {
        heading: `Sul tuo dispositivo`,
        body: [
          `Quando rispondi a una richiesta, il browser crea la tua chiave di firma di mittente e la tiene nella memoria locale (localStorage) di sigylo.net, così il tuo codice mittente resta sempre lo stesso. Non ci viene mai inviata e non ti identifica presso di noi: in ogni risposta firmata viaggia solo la chiave pubblica, cifrata insieme al segreto, che soltanto il destinatario può leggere. Puoi cancellarla quando vuoi eliminando i dati del sito dal browser.`,
        ],
      },
      {
        heading: `Per quanto tempo`,
        body: [
          `I dati vengono cancellati alla prima lettura, alla revoca o alla scadenza, al massimo dopo 7 giorni. Un file a lettura unica viene cancellato pezzo per pezzo mentre lo scarichi; se il download si interrompe, ciò che resta scade entro un'ora. Ciò che scade viene eliminato fisicamente entro circa 15 minuti. Le eventuali copie di ripristino dei fornitori contengono gli stessi dati cifrati e si rinnovano secondo i loro cicli.`,
        ],
      },
      {
        heading: `Dati di rete`,
        body: [
          `Per consegnare la pagina e proteggere il servizio, Cloudflare tratta il tuo indirizzo IP e i dati tecnici della richiesta. Sigylo usa l'indirizzo IP solo per limitare le scritture (30 al minuto), in memoria presso Cloudflare, senza salvarlo; i log del Worker sono disattivati. Cloudflare può conservare dati di sicurezza secondo la propria informativa.`,
          `Per gli account limitiamo anche i tentativi di accesso (10 al minuto per account), sempre in memoria presso Cloudflare, legati all'hash dell'account e non al tuo indirizzo.`,
        ],
      },
      {
        heading: `Basi giuridiche`,
        body: [
          `Fornirti il servizio che chiedi (articolo 6, paragrafo 1, lettera b, del GDPR) e il legittimo interesse a proteggere il servizio dagli abusi (articolo 6, paragrafo 1, lettera f).`,
        ],
      },
      {
        heading: `Fornitori e trasferimenti`,
        body: [
          `Cloudflare, Inc.: hosting, rete e limitazione della frequenza, su una rete globale, e archiviazione dei pezzi cifrati dei file su Cloudflare R2 nella giurisdizione dell'Unione europea; i trasferimenti verso gli Stati Uniti si basano sull'EU-U.S. Data Privacy Framework e sulle clausole contrattuali tipo.`,
          `Supabase, Inc.: database PostgreSQL ospitato nella regione eu-central-1 (Francoforte, Germania). Entrambi agiscono come responsabili del trattamento in base ai rispettivi accordi sul trattamento dei dati.`,
        ],
      },
      {
        heading: `I tuoi diritti`,
        body: [
          `Hai diritto di accesso, rettifica, cancellazione, limitazione, opposizione e portabilità (articoli 15-22 del GDPR). Poiché non conserviamo identificativi, di norma non possiamo collegare alcun dato a te (articolo 11); puoi però distruggere un segreto in qualsiasi momento con il link di revoca o aprendolo. Per ogni richiesta scrivi a ${email}.`,
          `Se hai un account, puoi cancellarlo con tutti i suoi dati in qualsiasi momento dalla pagina dell'account.`,
          `Puoi proporre reclamo al Garante per la protezione dei dati personali (garanteprivacy.it) o all'autorità di controllo del tuo Paese. Non prendiamo decisioni automatizzate che ti riguardano.`,
        ],
      },
    ],
  },
};

const en: LegalTexts = {
  terms: {
    title: `Terms of Service`,
    sections: [
      {
        heading: `Who provides the service`,
        body: [
          `Sigylo, at sigylo.net, is a free service provided by ${name} (Italy), reachable at ${email}. By using the service you accept these terms. If you do not accept them, do not use it.`,
        ],
      },
      {
        heading: `How it works and what we cannot do`,
        body: [
          `Your secret is encrypted on your device before it leaves. We only keep unreadable data: the key lives in the link, which never reaches our servers.`,
          `That is why we cannot read, recover or rebuild a secret. If you lose the link, the secret is lost. Anyone holding the link can open it: share it only with the intended recipient and, for the most sensitive data, add a passphrase sent through another channel.`,
          `A secret is destroyed at its first read or at the expiry you chose, after 7 days at most. In request mode we cannot know who sealed the answer.`,
        ],
      },
      {
        heading: `Acceptable use`,
        body: [
          `You may use Sigylo for lawful purposes only. You may not use it to spread illegal content, malware or phishing material, to infringe the rights of others or to harass anyone.`,
          `You may not attack the service, overload it, bypass its rate limits or try to reach other people's data. We may restrict or block access for anyone who breaks these rules.`,
        ],
      },
      {
        heading: `Reports and authorities`,
        body: [
          `The single point of contact for users and authorities under Regulation (EU) 2022/2065 (Digital Services Act) is ${email}, in Italian or English.`,
          `As we cannot see any content, we can only act on a specific link reported to us: in that case we can destroy the secret it points to.`,
        ],
      },
      {
        heading: `Free service, no warranties`,
        body: [
          `The service is provided free of charge, as is and as available. We may change, suspend or close it at any time. Do not use Sigylo as the only copy of data you cannot afford to lose.`,
        ],
      },
      {
        heading: `Liability`,
        body: [
          `To the extent permitted by law, we are not liable for indirect damages, data loss or the use of links by those who receive them. Liability for wilful misconduct or gross negligence (article 1229 of the Italian Civil Code) and the consumer rights that the law does not allow to be excluded remain unaffected.`,
        ],
      },
      {
        heading: `Open source and the Apache License 2.0`,
        body: [
          `The source code of Sigylo is distributed under the Apache License 2.0. The licence governs copying, modifying and redistributing the code, including its disclaimer of warranty (section 7) and limitation of liability (section 8). These terms govern only the use of the service at sigylo.net: whoever runs their own copy of the code follows the licence, not these terms.`,
          `The licence grants no trademark rights (section 6): the name Sigylo and its logo identify this service, and a modified version must use another name. Third-party components keep their own licences; the attributions are in the NOTICE file of the code.`,
        ],
      },
      {
        heading: `Changes and governing law`,
        body: [
          `We may update these terms; the date of the last update is shown at the top. Italian law applies. If you are a consumer, the mandatory protections of your country and the courts of your place of residence remain available to you. If the translations differ, the Italian text prevails.`,
        ],
      },
    ],
  },
  privacy: {
    title: `Privacy Notice`,
    sections: [
      {
        heading: `Controller`,
        body: [
          `${name} (Italy), ${email}. This notice is given under articles 13 and 14 of Regulation (EU) 2016/679 (GDPR).`,
        ],
      },
      {
        heading: `In short`,
        body: [
          `Optional accounts without e-mail, no cookies, no tracking, no analytics. We cannot read what you seal: it is encrypted on your device and the key never reaches our servers.`,
        ],
      },
      {
        heading: `What we keep`,
        body: [
          `For each secret: the encrypted envelope, its expiry, its destruction rule and the SHA-256 digest of the revocation code. For each request: the public key of whoever creates it and, once it arrives, the encrypted answer. For a file, in addition: its encrypted pieces (on Cloudflare R2, in the European Union, under random names), how many there are and, once opened, the SHA-256 digest of the code that releases them only to whoever opened it.`,
          `Nothing else: no creation time, no IP address, no identity. Even if a secret contains personal data, it stays unreadable to us.`,
        ],
      },
      {
        heading: `Optional accounts`,
        body: [
          `If you create an account we keep: a keyed hash of your username (not the name itself), the OPAQUE registration record (your password never reaches us, not even as a hash) and your keyring, encrypted on your device with a key we never see, with a counter of its changes. The keyring holds the codes to destroy the secrets you sealed while signed in, not the links that open them.`,
          `While you are signed in we keep the SHA-256 digest of your session code and its expiry, 12 hours at most; during a sign-in, for five minutes, the state of the protocol. The account stays until you delete it from the account page, which erases everything at once.`,
          ],
        },
        {
        heading: `On your device`,
        body: [
          `When you answer a request, your browser creates your sender signing key and keeps it in the local storage (localStorage) of sigylo.net, so your sender code stays the same. It is never sent to us and does not identify you to us: each signed answer carries only the public key, encrypted together with the secret, which only the recipient can read. You can delete it at any time by clearing the site data in your browser.`,
        ],
      },
      {
        heading: `For how long`,
        body: [
          `Data is deleted at the first read, on revocation or at expiry, after 7 days at most. A burn-after-reading file is deleted piece by piece as it downloads; if the download stops, what is left expires within an hour. Whatever expires is physically removed within about 15 minutes. Any recovery copies held by our providers contain the same encrypted data and roll over on their own cycles.`,
        ],
      },
      {
        heading: `Network data`,
        body: [
          `To deliver the page and protect the service, Cloudflare processes your IP address and the technical data of each request. Sigylo uses the IP address only to limit writes (30 per minute), in memory at Cloudflare, without storing it; Worker logs are switched off. Cloudflare may keep security data under its own privacy policy.`,
          `For accounts we also limit sign-in attempts (10 per minute per account), again in memory at Cloudflare, tied to the account's hash rather than to your address.`,
        ],
      },
      {
        heading: `Legal bases`,
        body: [
          `Providing the service you ask for (article 6(1)(b) GDPR) and our legitimate interest in protecting the service from abuse (article 6(1)(f)).`,
        ],
      },
      {
        heading: `Providers and transfers`,
        body: [
          `Cloudflare, Inc.: hosting, network and rate limiting, on a global network, and storage of the encrypted pieces of files on Cloudflare R2 in the European Union jurisdiction; transfers to the United States rely on the EU-U.S. Data Privacy Framework and the standard contractual clauses.`,
          `Supabase, Inc.: PostgreSQL database hosted in the eu-central-1 region (Frankfurt, Germany). Both act as processors under their data processing agreements.`,
        ],
      },
      {
        heading: `Your rights`,
        body: [
          `You have the rights of access, rectification, erasure, restriction, objection and portability (articles 15-22 GDPR). Since we keep no identifiers, we usually cannot link any data to you (article 11); you can however destroy a secret at any time with the revocation link or by opening it. For any request, write to ${email}.`,
          `If you have an account, you can delete it with all its data at any time from the account page.`,
          `You may lodge a complaint with the Italian Garante per la protezione dei dati personali (garanteprivacy.it) or with the supervisory authority of your country. We make no automated decisions about you.`,
        ],
      },
    ],
  },
};

const fr: LegalTexts = {
  terms: {
    title: `Conditions d'utilisation`,
    sections: [
      {
        heading: `Qui fournit le service`,
        body: [
          `Sigylo, à l'adresse sigylo.net, est un service gratuit fourni par ${name} (Italie), joignable à ${email}. En utilisant le service, vous acceptez ces conditions. Si vous ne les acceptez pas, ne l'utilisez pas.`,
        ],
      },
      {
        heading: `Fonctionnement et limites`,
        body: [
          `Votre secret est chiffré sur votre appareil avant de partir. Nous ne conservons que des données illisibles : la clé se trouve dans le lien, qui n'atteint jamais nos serveurs.`,
          `C'est pourquoi nous ne pouvons ni lire, ni récupérer, ni reconstituer un secret. Si vous perdez le lien, le secret est perdu. Toute personne qui a le lien peut l'ouvrir : partagez-le uniquement avec le destinataire et, pour les données les plus sensibles, ajoutez une phrase secrète envoyée par un autre canal.`,
          `Un secret est détruit à sa première lecture ou à l'expiration choisie, au plus tard après 7 jours. En mode demande, nous ne pouvons pas savoir qui a scellé la réponse.`,
        ],
      },
      {
        heading: `Usage autorisé`,
        body: [
          `Vous ne pouvez utiliser Sigylo qu'à des fins licites. Il est interdit de l'utiliser pour diffuser des contenus illégaux, des logiciels malveillants ou du hameçonnage, pour porter atteinte aux droits d'autrui ou pour harceler quiconque.`,
          `Il est interdit d'attaquer le service, de le surcharger, de contourner ses limites de fréquence ou de tenter d'accéder aux données d'autrui. Nous pouvons restreindre ou bloquer l'accès de quiconque enfreint ces règles.`,
        ],
      },
      {
        heading: `Signalements et autorités`,
        body: [
          `Le point de contact unique pour les utilisateurs et les autorités, au sens du règlement (UE) 2022/2065 sur les services numériques, est ${email}, en italien ou en anglais.`,
          `Comme nous ne voyons aucun contenu, nous ne pouvons agir que sur un lien précis qui nous est signalé : nous pouvons alors détruire le secret auquel il renvoie.`,
        ],
      },
      {
        heading: `Service gratuit, sans garantie`,
        body: [
          `Le service est fourni gratuitement, en l'état et selon sa disponibilité. Nous pouvons le modifier, le suspendre ou le fermer à tout moment. N'utilisez pas Sigylo comme seule copie d'une donnée que vous ne pouvez pas vous permettre de perdre.`,
        ],
      },
      {
        heading: `Responsabilité`,
        body: [
          `Dans les limites permises par la loi, nous ne répondons pas des dommages indirects, de la perte de données ni de l'usage des liens par ceux qui les reçoivent. La responsabilité pour faute intentionnelle ou lourde (article 1229 du code civil italien) et les droits des consommateurs auxquels la loi ne permet pas de déroger restent intacts.`,
        ],
      },
      {
        heading: `Code ouvert et Apache License 2.0`,
        body: [
          `Le code source de Sigylo est distribué sous Apache License 2.0. La licence régit la copie, la modification et la redistribution du code, y compris son exclusion de garantie (section 7) et sa limitation de responsabilité (section 8). Ces conditions ne régissent que l'utilisation du service sur sigylo.net : quiconque exécute sa propre copie du code suit la licence, pas ces conditions.`,
          `La licence n'accorde aucun droit sur les marques (section 6) : le nom Sigylo et son logo identifient ce service, et une version modifiée doit porter un autre nom. Les composants tiers restent soumis à leurs propres licences ; les attributions figurent dans le fichier NOTICE du code.`,
        ],
      },
      {
        heading: `Modifications et droit applicable`,
        body: [
          `Nous pouvons mettre à jour ces conditions ; la date de la dernière mise à jour figure en haut. Le droit italien s'applique. Si vous êtes un consommateur, les protections impératives de votre pays et les tribunaux de votre lieu de résidence vous restent ouverts. En cas de divergence entre les traductions, le texte italien prévaut.`,
        ],
      },
    ],
  },
  privacy: {
    title: `Politique de confidentialité`,
    sections: [
      {
        heading: `Responsable du traitement`,
        body: [
          `${name} (Italie), ${email}. Cette information est fournie au titre des articles 13 et 14 du règlement (UE) 2016/679 (RGPD).`,
        ],
      },
      {
        heading: `En bref`,
        body: [
          `Des comptes facultatifs et sans e-mail, aucun cookie, aucun pistage, aucune mesure d'audience. Nous ne pouvons pas lire ce que vous scellez : c'est chiffré sur votre appareil et la clé n'atteint jamais nos serveurs.`,
        ],
      },
      {
        heading: `Ce que nous conservons`,
        body: [
          `Pour chaque secret : l'enveloppe chiffrée, son expiration, sa règle de destruction et l'empreinte SHA-256 du code de révocation. Pour chaque demande : la clé publique de son auteur et, si elle arrive, la réponse chiffrée. Pour un fichier, en plus : ses morceaux chiffrés (sur Cloudflare R2, dans l'Union européenne, sous des noms aléatoires), leur nombre et, après l'ouverture, l'empreinte SHA-256 du code qui ne les remet qu'à la personne qui l'a ouvert.`,
          `Rien d'autre : ni heure de création, ni adresse IP, ni identité. Même si un secret contient des données personnelles, il reste illisible pour nous.`,
        ],
      },
      {
        heading: `Comptes facultatifs`,
        body: [
          `Si vous créez un compte, nous conservons : un hachage à clé de votre nom d'utilisateur (pas le nom lui-même), l'enregistrement OPAQUE (votre mot de passe ne nous parvient jamais, pas même sous forme de hachage) et votre trousseau, chiffré sur votre appareil avec une clé que nous ne voyons jamais, avec un compteur de ses modifications. Le trousseau contient les codes pour détruire les secrets que vous avez scellés une fois connecté, pas les liens qui les ouvrent.`,
          `Tant que vous êtes connecté, nous conservons l'empreinte SHA-256 de votre code de session et son expiration, 12 heures au plus ; pendant une connexion, pendant cinq minutes, l'état du protocole. Le compte reste jusqu'à ce que vous le supprimiez depuis la page du compte, ce qui efface tout en une fois.`,
          ],
        },
        {
        heading: `Sur votre appareil`,
        body: [
          `Lorsque vous répondez à une demande, votre navigateur crée votre clé de signature d'expéditeur et la garde dans le stockage local (localStorage) de sigylo.net, afin que votre code d'expéditeur reste le même. Elle ne nous est jamais envoyée et ne vous identifie pas auprès de nous : chaque réponse signée ne transporte que la clé publique, chiffrée avec le secret, que seul le destinataire peut lire. Vous pouvez la supprimer à tout moment en effaçant les données du site dans votre navigateur.`,
        ],
      },
      {
        heading: `Pendant combien de temps`,
        body: [
          `Les données sont supprimées à la première lecture, à la révocation ou à l'expiration, au plus tard après 7 jours. Un fichier à lecture unique est supprimé morceau par morceau pendant son téléchargement ; si celui-ci s'interrompt, le reste expire dans l'heure. Ce qui expire est effacé physiquement en 15 minutes environ. Les éventuelles copies de restauration de nos prestataires contiennent les mêmes données chiffrées et se renouvellent selon leurs propres cycles.`,
        ],
      },
      {
        heading: `Données réseau`,
        body: [
          `Pour délivrer la page et protéger le service, Cloudflare traite votre adresse IP et les données techniques de chaque requête. Sigylo n'utilise l'adresse IP que pour limiter les écritures (30 par minute), en mémoire chez Cloudflare, sans la conserver ; les journaux du Worker sont désactivés. Cloudflare peut conserver des données de sécurité selon sa propre politique de confidentialité.`,
          `Pour les comptes, nous limitons aussi les tentatives de connexion (10 par minute et par compte), toujours en mémoire chez Cloudflare, liées au hachage du compte et non à votre adresse.`,
        ],
      },
      {
        heading: `Bases légales`,
        body: [
          `La fourniture du service que vous demandez (article 6, paragraphe 1, point b, du RGPD) et notre intérêt légitime à protéger le service contre les abus (article 6, paragraphe 1, point f).`,
        ],
      },
      {
        heading: `Prestataires et transferts`,
        body: [
          `Cloudflare, Inc. : hébergement, réseau et limitation de fréquence, sur un réseau mondial, et stockage des morceaux chiffrés des fichiers sur Cloudflare R2 dans la juridiction de l'Union européenne ; les transferts vers les États-Unis reposent sur l'EU-U.S. Data Privacy Framework et les clauses contractuelles types.`,
          `Supabase, Inc. : base de données PostgreSQL hébergée dans la région eu-central-1 (Francfort, Allemagne). Tous deux agissent en tant que sous-traitants selon leurs accords de traitement des données.`,
        ],
      },
      {
        heading: `Vos droits`,
        body: [
          `Vous disposez des droits d'accès, de rectification, d'effacement, de limitation, d'opposition et de portabilité (articles 15 à 22 du RGPD). Comme nous ne conservons aucun identifiant, nous ne pouvons généralement relier aucune donnée à vous (article 11) ; vous pouvez toutefois détruire un secret à tout moment avec le lien de révocation ou en l'ouvrant. Pour toute demande, écrivez à ${email}.`,
          `Si vous avez un compte, vous pouvez le supprimer avec toutes ses données à tout moment depuis la page du compte.`,
          `Vous pouvez introduire une réclamation auprès du Garante per la protezione dei dati personali italien (garanteprivacy.it) ou de l'autorité de contrôle de votre pays, comme la CNIL. Nous ne prenons aucune décision automatisée vous concernant.`,
        ],
      },
    ],
  },
};

const es: LegalTexts = {
  terms: {
    title: `Términos del servicio`,
    sections: [
      {
        heading: `Quién ofrece el servicio`,
        body: [
          `Sigylo, en sigylo.net, es un servicio gratuito ofrecido por ${name} (Italia), con quien puedes contactar en ${email}. Al usar el servicio aceptas estos términos. Si no los aceptas, no lo uses.`,
        ],
      },
      {
        heading: `Cómo funciona y qué no podemos hacer`,
        body: [
          `Tu secreto se cifra en tu dispositivo antes de salir. Solo guardamos datos ilegibles: la clave está en el enlace, que nunca llega a nuestros servidores.`,
          `Por eso no podemos leer, recuperar ni reconstruir un secreto. Si pierdes el enlace, el secreto se pierde. Cualquiera que tenga el enlace puede abrirlo: compártelo solo con quien deba recibirlo y, para los datos más delicados, añade una frase de contraseña enviada por otro canal.`,
          `Un secreto se destruye en su primera lectura o al vencer el plazo elegido, como máximo a los 7 días. En el modo solicitud no podemos saber quién selló la respuesta.`,
        ],
      },
      {
        heading: `Uso permitido`,
        body: [
          `Solo puedes usar Sigylo con fines lícitos. Está prohibido usarlo para difundir contenidos ilegales, malware o material de phishing, para vulnerar derechos ajenos o para acosar a nadie.`,
          `Está prohibido atacar el servicio, sobrecargarlo, eludir sus límites de frecuencia o intentar acceder a datos ajenos. Podemos restringir o bloquear el acceso a quien incumpla estas normas.`,
        ],
      },
      {
        heading: `Notificaciones y autoridades`,
        body: [
          `El punto de contacto único para usuarios y autoridades, conforme al Reglamento (UE) 2022/2065 de servicios digitales, es ${email}, en italiano o en inglés.`,
          `Como no vemos ningún contenido, solo podemos actuar sobre un enlace concreto que se nos notifique: en ese caso podemos destruir el secreto al que apunta.`,
        ],
      },
      {
        heading: `Servicio gratuito, sin garantías`,
        body: [
          `El servicio se ofrece gratis, tal cual y según disponibilidad. Podemos modificarlo, suspenderlo o cerrarlo en cualquier momento. No uses Sigylo como única copia de un dato que no te puedas permitir perder.`,
        ],
      },
      {
        heading: `Responsabilidad`,
        body: [
          `En la medida en que lo permita la ley, no respondemos de daños indirectos, pérdida de datos ni del uso de los enlaces por parte de quien los recibe. Se mantienen la responsabilidad por dolo o culpa grave (artículo 1229 del Código Civil italiano) y los derechos de los consumidores que la ley no permite excluir.`,
        ],
      },
      {
        heading: `Código abierto y Apache License 2.0`,
        body: [
          `El código fuente de Sigylo se distribuye con la Apache License 2.0. La licencia regula la copia, la modificación y la redistribución del código, incluidas su exclusión de garantía (sección 7) y su limitación de responsabilidad (sección 8). Estos términos regulan solo el uso del servicio en sigylo.net: quien ejecute su propia copia del código sigue la licencia, no estos términos.`,
          `La licencia no concede derechos sobre marcas (sección 6): el nombre Sigylo y su logotipo identifican este servicio, y una versión modificada debe usar otro nombre. Los componentes de terceros conservan sus propias licencias; las atribuciones están en el archivo NOTICE del código.`,
        ],
      },
      {
        heading: `Cambios y ley aplicable`,
        body: [
          `Podemos actualizar estos términos; la fecha de la última actualización figura arriba. Se aplica la ley italiana. Si eres consumidor, conservas las protecciones imperativas de tu país y los tribunales de tu lugar de residencia. Si las traducciones difieren, prevalece el texto italiano.`,
        ],
      },
    ],
  },
  privacy: {
    title: `Aviso de privacidad`,
    sections: [
      {
        heading: `Responsable del tratamiento`,
        body: [
          `${name} (Italia), ${email}. Este aviso se ofrece conforme a los artículos 13 y 14 del Reglamento (UE) 2016/679 (RGPD).`,
        ],
      },
      {
        heading: `En resumen`,
        body: [
          `Cuentas opcionales y sin correo electrónico, sin cookies, sin rastreo, sin analítica. No podemos leer lo que sellas: se cifra en tu dispositivo y la clave nunca llega a nuestros servidores.`,
        ],
      },
      {
        heading: `Qué guardamos`,
        body: [
          `Para cada secreto: el sobre cifrado, su vencimiento, su regla de destrucción y la huella SHA-256 del código de revocación. Para cada solicitud: la clave pública de quien la crea y, si llega, la respuesta cifrada. Para un archivo, además: sus fragmentos cifrados (en Cloudflare R2, en la Unión Europea, con nombres aleatorios), cuántos son y, tras abrirlo, la huella SHA-256 del código que solo se los entrega a quien lo abrió.`,
          `Nada más: ni hora de creación, ni dirección IP, ni identidad. Aunque un secreto contenga datos personales, para nosotros sigue siendo ilegible.`,
        ],
      },
      {
        heading: `Cuentas opcionales`,
        body: [
          `Si creas una cuenta guardamos: un hash con clave de tu nombre de usuario (no el nombre), el registro OPAQUE (tu contraseña nunca nos llega, ni siquiera como hash) y tu llavero, cifrado en tu dispositivo con una clave que nunca vemos, con un contador de sus cambios. El llavero contiene los códigos para destruir los secretos que sellaste con la sesión iniciada, no los enlaces que los abren.`,
          `Mientras tienes la sesión iniciada guardamos la huella SHA-256 de tu código de sesión y su vencimiento, 12 horas como máximo; durante un inicio de sesión, durante cinco minutos, el estado del protocolo. La cuenta se mantiene hasta que la eliminas desde la página de la cuenta, que lo borra todo de una vez.`,
          ],
        },
        {
        heading: `En tu dispositivo`,
        body: [
          `Cuando respondes a una solicitud, tu navegador crea tu clave de firma de remitente y la guarda en el almacenamiento local (localStorage) de sigylo.net, para que tu código de remitente sea siempre el mismo. Nunca se nos envía y no te identifica ante nosotros: cada respuesta firmada lleva solo la clave pública, cifrada junto con el secreto, que solo el destinatario puede leer. Puedes borrarla cuando quieras eliminando los datos del sitio en tu navegador.`,
        ],
      },
      {
        heading: `Durante cuánto tiempo`,
        body: [
          `Los datos se borran en la primera lectura, con la revocación o al vencer, como máximo a los 7 días. Un archivo de lectura única se borra fragmento a fragmento mientras se descarga; si la descarga se interrumpe, lo que queda vence en una hora. Lo que vence se elimina físicamente en unos 15 minutos. Las posibles copias de restauración de nuestros proveedores contienen los mismos datos cifrados y se renuevan según sus propios ciclos.`,
        ],
      },
      {
        heading: `Datos de red`,
        body: [
          `Para entregar la página y proteger el servicio, Cloudflare trata tu dirección IP y los datos técnicos de cada petición. Sigylo usa la dirección IP solo para limitar las escrituras (30 por minuto), en memoria en Cloudflare, sin guardarla; los registros del Worker están desactivados. Cloudflare puede conservar datos de seguridad según su propia política de privacidad.`,
          `Para las cuentas limitamos también los intentos de inicio de sesión (10 por minuto y cuenta), igualmente en memoria en Cloudflare, ligados al hash de la cuenta y no a tu dirección.`,
        ],
      },
      {
        heading: `Bases jurídicas`,
        body: [
          `Prestarte el servicio que solicitas (artículo 6, apartado 1, letra b, del RGPD) y nuestro interés legítimo en proteger el servicio frente a abusos (artículo 6, apartado 1, letra f).`,
        ],
      },
      {
        heading: `Proveedores y transferencias`,
        body: [
          `Cloudflare, Inc.: alojamiento, red y limitación de frecuencia, en una red global, y almacenamiento de los fragmentos cifrados de los archivos en Cloudflare R2 en la jurisdicción de la Unión Europea; las transferencias a Estados Unidos se basan en el EU-U.S. Data Privacy Framework y en las cláusulas contractuales tipo.`,
          `Supabase, Inc.: base de datos PostgreSQL alojada en la región eu-central-1 (Fráncfort, Alemania). Ambos actúan como encargados del tratamiento según sus acuerdos de tratamiento de datos.`,
        ],
      },
      {
        heading: `Tus derechos`,
        body: [
          `Tienes derecho de acceso, rectificación, supresión, limitación, oposición y portabilidad (artículos 15 a 22 del RGPD). Como no guardamos identificadores, normalmente no podemos vincular ningún dato contigo (artículo 11); aun así, puedes destruir un secreto en cualquier momento con el enlace de revocación o abriéndolo. Para cualquier solicitud, escribe a ${email}.`,
          `Si tienes una cuenta, puedes eliminarla con todos sus datos en cualquier momento desde la página de la cuenta.`,
          `Puedes presentar una reclamación ante el Garante per la protezione dei dati personali italiano (garanteprivacy.it) o ante la autoridad de control de tu país, como la AEPD. No tomamos decisiones automatizadas sobre ti.`,
        ],
      },
    ],
  },
};

const de: LegalTexts = {
  terms: {
    title: `Nutzungsbedingungen`,
    sections: [
      {
        heading: `Wer den Dienst anbietet`,
        body: [
          `Sigylo unter sigylo.net ist ein kostenloser Dienst von ${name} (Italien), erreichbar unter ${email}. Mit der Nutzung des Dienstes akzeptierst du diese Bedingungen. Wenn du sie nicht akzeptierst, nutze ihn nicht.`,
        ],
      },
      {
        heading: `Wie es funktioniert und was wir nicht können`,
        body: [
          `Dein Geheimnis wird auf deinem Gerät verschlüsselt, bevor es losgeschickt wird. Wir speichern nur unlesbare Daten: Der Schlüssel steckt im Link, der unsere Server nie erreicht.`,
          `Deshalb können wir ein Geheimnis weder lesen noch wiederherstellen oder rekonstruieren. Geht der Link verloren, ist das Geheimnis verloren. Wer den Link hat, kann es öffnen: Teile ihn nur mit dem vorgesehenen Empfänger und füge bei besonders sensiblen Daten eine Passphrase hinzu, die du über einen anderen Kanal sendest.`,
          `Ein Geheimnis wird beim ersten Lesen oder zum gewählten Ablauf vernichtet, spätestens nach 7 Tagen. Im Anfragemodus können wir nicht wissen, wer die Antwort versiegelt hat.`,
        ],
      },
      {
        heading: `Erlaubte Nutzung`,
        body: [
          `Du darfst Sigylo nur für rechtmäßige Zwecke nutzen. Verboten ist es, damit rechtswidrige Inhalte, Schadsoftware oder Phishing-Material zu verbreiten, Rechte anderer zu verletzen oder jemanden zu belästigen.`,
          `Verboten ist es, den Dienst anzugreifen, zu überlasten, seine Ratenbegrenzung zu umgehen oder auf Daten anderer zuzugreifen. Wer gegen diese Regeln verstößt, dem können wir den Zugang einschränken oder sperren.`,
        ],
      },
      {
        heading: `Meldungen und Behörden`,
        body: [
          `Die zentrale Kontaktstelle für Nutzer und Behörden nach der Verordnung (EU) 2022/2065 über digitale Dienste ist ${email}, auf Italienisch oder Englisch.`,
          `Da wir keine Inhalte sehen, können wir nur bei einem konkreten, uns gemeldeten Link handeln: Dann können wir das Geheimnis vernichten, auf das er verweist.`,
        ],
      },
      {
        heading: `Kostenloser Dienst ohne Gewähr`,
        body: [
          `Der Dienst wird kostenlos, wie er ist und nach Verfügbarkeit angeboten. Wir können ihn jederzeit ändern, unterbrechen oder einstellen. Nutze Sigylo nicht als einzige Kopie von Daten, deren Verlust du dir nicht leisten kannst.`,
        ],
      },
      {
        heading: `Haftung`,
        body: [
          `Soweit gesetzlich zulässig, haften wir nicht für indirekte Schäden, Datenverlust oder die Nutzung der Links durch ihre Empfänger. Die Haftung für Vorsatz und grobe Fahrlässigkeit (Artikel 1229 des italienischen Zivilgesetzbuchs) und die Verbraucherrechte, die gesetzlich nicht ausgeschlossen werden können, bleiben unberührt.`,
        ],
      },
      {
        heading: `Offener Quellcode und Apache License 2.0`,
        body: [
          `Der Quellcode von Sigylo steht unter der Apache License 2.0. Die Lizenz regelt das Kopieren, Ändern und Weitergeben des Codes, einschließlich ihres Gewährleistungsausschlusses (Abschnitt 7) und ihrer Haftungsbeschränkung (Abschnitt 8). Diese Bedingungen regeln nur die Nutzung des Dienstes unter sigylo.net: Wer eine eigene Kopie des Codes betreibt, folgt der Lizenz, nicht diesen Bedingungen.`,
          `Die Lizenz gewährt keine Markenrechte (Abschnitt 6): Der Name Sigylo und sein Logo kennzeichnen diesen Dienst, und eine veränderte Version muss einen anderen Namen tragen. Komponenten Dritter unterliegen weiter ihren eigenen Lizenzen; die Hinweise stehen in der NOTICE-Datei des Codes.`,
        ],
      },
      {
        heading: `Änderungen und anwendbares Recht`,
        body: [
          `Wir können diese Bedingungen aktualisieren; das Datum der letzten Änderung steht oben. Es gilt italienisches Recht. Als Verbraucher behältst du die zwingenden Schutzvorschriften deines Landes und den Gerichtsstand deines Wohnorts. Weichen die Übersetzungen voneinander ab, gilt der italienische Text.`,
        ],
      },
    ],
  },
  privacy: {
    title: `Datenschutzhinweis`,
    sections: [
      {
        heading: `Verantwortlicher`,
        body: [
          `${name} (Italien), ${email}. Dieser Hinweis erfolgt nach den Artikeln 13 und 14 der Verordnung (EU) 2016/679 (DSGVO).`,
        ],
      },
      {
        heading: `Kurz gesagt`,
        body: [
          `Optionale Konten ohne E-Mail, keine Cookies, kein Tracking, keine Analyse. Wir können nicht lesen, was du versiegelst: Es wird auf deinem Gerät verschlüsselt, und der Schlüssel erreicht unsere Server nie.`,
        ],
      },
      {
        heading: `Was wir speichern`,
        body: [
          `Für jedes Geheimnis: den verschlüsselten Umschlag, den Ablauf, die Vernichtungsregel und den SHA-256-Fingerabdruck des Widerrufscodes. Für jede Anfrage: den öffentlichen Schlüssel der Person, die sie erstellt, und, falls sie eintrifft, die verschlüsselte Antwort. Bei einer Datei zusätzlich: ihre verschlüsselten Teile (auf Cloudflare R2, in der Europäischen Union, unter zufälligen Namen), deren Anzahl und, nach dem Öffnen, den SHA-256-Fingerabdruck des Codes, der sie nur an die Person ausgibt, die sie geöffnet hat.`,
          `Sonst nichts: keine Erstellungszeit, keine IP-Adresse, keine Identität. Selbst wenn ein Geheimnis personenbezogene Daten enthält, bleibt es für uns unlesbar.`,
        ],
      },
      {
        heading: `Optionale Konten`,
        body: [
          `Wenn du ein Konto erstellst, speichern wir: einen schlüsselbasierten Hash deines Benutzernamens (nicht den Namen selbst), den OPAQUE-Registrierungsdatensatz (dein Passwort erreicht uns nie, nicht einmal als Hash) und deinen Schlüsselbund, verschlüsselt auf deinem Gerät mit einem Schlüssel, den wir nie sehen, samt einem Zähler seiner Änderungen. Der Schlüsselbund enthält die Codes zum Vernichten der Geheimnisse, die du angemeldet versiegelt hast, nicht die Links, die sie öffnen.`,
          `Solange du angemeldet bist, speichern wir den SHA-256-Fingerabdruck deines Sitzungscodes und seinen Ablauf, höchstens 12 Stunden; während einer Anmeldung fünf Minuten lang den Zustand des Protokolls. Das Konto bleibt, bis du es auf der Kontoseite löschst; das löscht alles auf einmal.`,
          ],
        },
        {
        heading: `Auf deinem Gerät`,
        body: [
          `Wenn du eine Anfrage beantwortest, erzeugt dein Browser deinen Absender-Signaturschlüssel und bewahrt ihn im lokalen Speicher (localStorage) von sigylo.net auf, damit dein Absendercode gleich bleibt. Er wird nie an uns gesendet und identifiziert dich uns gegenüber nicht: Jede signierte Antwort enthält nur den öffentlichen Schlüssel, zusammen mit dem Geheimnis verschlüsselt, den nur die empfangende Person lesen kann. Du kannst ihn jederzeit löschen, indem du die Websitedaten in deinem Browser entfernst.`,
        ],
      },
      {
        heading: `Wie lange`,
        body: [
          `Die Daten werden beim ersten Lesen, beim Widerruf oder zum Ablauf gelöscht, spätestens nach 7 Tagen. Eine Datei zum einmaligen Lesen wird beim Herunterladen Teil für Teil gelöscht; bricht der Download ab, läuft der Rest binnen einer Stunde ab. Was abläuft, wird binnen etwa 15 Minuten physisch entfernt. Etwaige Wiederherstellungskopien unserer Anbieter enthalten dieselben verschlüsselten Daten und erneuern sich nach deren eigenen Zyklen.`,
        ],
      },
      {
        heading: `Netzwerkdaten`,
        body: [
          `Um die Seite auszuliefern und den Dienst zu schützen, verarbeitet Cloudflare deine IP-Adresse und die technischen Daten jeder Anfrage. Sigylo nutzt die IP-Adresse nur, um Schreibvorgänge zu begrenzen (30 pro Minute), im Speicher bei Cloudflare, ohne sie zu speichern; die Worker-Protokolle sind abgeschaltet. Cloudflare kann Sicherheitsdaten nach seiner eigenen Datenschutzerklärung aufbewahren.`,
          `Bei Konten begrenzen wir außerdem Anmeldeversuche (10 pro Minute und Konto), ebenfalls im Speicher bei Cloudflare, gebunden an den Hash des Kontos statt an deine Adresse.`,
        ],
      },
      {
        heading: `Rechtsgrundlagen`,
        body: [
          `Die Bereitstellung des von dir angefragten Dienstes (Artikel 6 Absatz 1 Buchstabe b DSGVO) und unser berechtigtes Interesse, den Dienst vor Missbrauch zu schützen (Artikel 6 Absatz 1 Buchstabe f).`,
        ],
      },
      {
        heading: `Anbieter und Übermittlungen`,
        body: [
          `Cloudflare, Inc.: Hosting, Netzwerk und Ratenbegrenzung in einem globalen Netz sowie Speicherung der verschlüsselten Teile von Dateien auf Cloudflare R2 im Rechtsraum der Europäischen Union; Übermittlungen in die Vereinigten Staaten stützen sich auf das EU-U.S. Data Privacy Framework und die Standardvertragsklauseln.`,
          `Supabase, Inc.: PostgreSQL-Datenbank in der Region eu-central-1 (Frankfurt, Deutschland). Beide handeln als Auftragsverarbeiter auf Grundlage ihrer Auftragsverarbeitungsverträge.`,
        ],
      },
      {
        heading: `Deine Rechte`,
        body: [
          `Du hast das Recht auf Auskunft, Berichtigung, Löschung, Einschränkung, Widerspruch und Datenübertragbarkeit (Artikel 15 bis 22 DSGVO). Da wir keine Kennungen speichern, können wir in der Regel keine Daten dir zuordnen (Artikel 11); du kannst ein Geheimnis aber jederzeit mit dem Widerrufslink oder durch Öffnen vernichten. Für jede Anfrage schreibe an ${email}.`,
          `Wenn du ein Konto hast, kannst du es mit allen Daten jederzeit auf der Kontoseite löschen.`,
          `Du kannst dich bei der italienischen Garante per la protezione dei dati personali (garanteprivacy.it) oder bei der Aufsichtsbehörde deines Landes beschweren. Wir treffen keine automatisierten Entscheidungen über dich.`,
        ],
      },
    ],
  },
};

export const legal: Record<Language, LegalTexts> = { it, en, fr, es, de };
