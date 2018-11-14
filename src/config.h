//#define DEBUG                                   // Show very lengthy debug output


// SIP Einstellungen
#define SIP_DOMAIN      "fritz.box"             // SIP Domain wo wir uns anmelden (unsere Fritz Box)
#define SIP_USER        "650"                   // Benutzername aus der Fritzbox Konfiguration
#define SIP_PASSWD      "SIPpassword123!"       // Passwort aus der Fritz Box Konfiguration
#define SIP_NAME        "Türklingel"            // Frei wählbarer Name der für den SIP Account angezeigt wird
#define MAX_RING_TIME   30000                   // Maximale Klingeldauer (in Millisekunden) (optional)
#define MAX_CALL_TIME   60000                   // Maximale Dauer eines Anrufs (in Millisekunden) (optional)

// Zeitplan und Nummern zum anrufen
#define NACHTRUHE_START 2200                    // Beginn der Nachtruhe (Klingel aus, alternative SIP URL)
#define NACHTRUHE_ENDE  800                     // Ende der Nachtruhe (Format hhmm mit hh=24 Stunden OHNE führender Null (!) und mm = zweistellige Minuten mit führender Null)
#define SIP_TAG_URI     "sip:**750@fritz.box"   // SIP URI die durch den Klingeltaster angerufen wird (tags)
#define SIP_NACHT_URI   "sip:**751@fritz.box"   // SIP URI die durch den Klingeltaster angerufen wird (nachts)

// Lautstärke
#define VOL_SPEAKER     7.5                     // Lautstärke Lautsprecher
#define VOL_MIC         2.0                     // Lautstärke Mikrofon

// Crypted Türcode und Ratenlimit
#include "code.h"                               // Türcode in eigener Datei
#define DTMF_MAX        10                      // maximale Länge für Türcode
#define RATE_LIMIT      120000                  // Zeitspanne für Versuche (in Millisekunden)
#define RATE_MAX        5                       // Maximale Anzahl von Versuchen in dieser Zeit

// Klingel/Glocken Dauern
#define TUER_LOOPS      1                       // Anzahl an an/aus Zyklen für den Türöffner
#define TUER_DAUER      2000                    // Dauer in Millisekunden für einen (halben) Türöffnerzyklus
#define GLOCKE_LOOPS    1                       // Anzahl an an/aus Zyklen für die Klingel
#define GLOCKE_DAUER    333                     // Dauer in Millisekunden für Glocke
#define KLINGEL_DAUER   100                     // Dauer in Millisekunden für Klingeltaster

// Pin Definitionen
#define KLINGEL_PIN     22                      // Pin auf dem der Klingeltaster liegt
#define TUER_PIN        17                      // Pin auf dem der Türöffner liegt
#define GLOCKE_PIN      27                      // Pin auf dem die Türglocke liegt

// Optionale Sicherheitseinstellungen
#define UNPRIV_USER     "klingel"               // Unpriviligierter Benutzer für Hauptprogram
                                                // Muss in audio Gruppe sein
#define FIFO_PFAD       "/run/klingel/klingel.pipe"      // Fifo für Türöffner

// UDPv6
//#define WITH_UDP6                               // UDPv6 via IPv6 statt altem UDP verwenden

// Optionale TLS Einstellungen
//#define WITH_TLS                                // TLS statt normalem UDP verwenden
//#define TLS_CERT_FILE           "cert.pem"      // Datei mit TLS Zertifikat
//#define TLS_PRIVKEY_FILE        "key.pem"       // Datei mit TLS Private Key
//#define TLS_PRIVKEY_PASSWORD    "geheim"        // TLS Private Key Passwort
