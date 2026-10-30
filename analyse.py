"""Analyse des journaux d'un pare-feu : nettoyage, résultats et figures."""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # enregistre les images sans ouvrir de fenêtre
import matplotlib.pyplot as plt
import pandas as pd

DOSSIER_PROJET = Path(__file__).parent
FICHIER_LOGS = DOSSIER_PROJET / "data" / "logs_reseau.csv"
FICHIER_RESULTATS = DOSSIER_PROJET / "resultats.json"
DOSSIER_FIGURES = DOSSIER_PROJET / "figures"

COULEUR_NORMALE = "#2a78d6"
COULEUR_ALERTE = "#eb6834"
NOMS_PORTS = {
    22: "22 (SSH)",
    23: "23 (Telnet)",
    53: "53 (DNS)",
    80: "80 (HTTP)",
    443: "443 (HTTPS)",
    1883: "1883 (MQTT)",
    8080: "8080 (HTTP alt.)",
}


def charger_donnees(chemin):
    """Lit le fichier CSV des logs et retourne un DataFrame."""
    return pd.read_csv(chemin)


def nettoyer_donnees(df):
    """Applique les 3 étapes de nettoyage demandées, dans l'ordre de l'énoncé."""
    # 1. Supprimer les doublons exacts
    df = df.drop_duplicates().copy()

    # 2. Mettre le protocole en majuscules
    df["protocol"] = df["protocol"].str.upper()

    # 3. Remplacer les bytes_sent manquants par la médiane
    #    (calculée ici, donc après la suppression des doublons)
    mediane = df["bytes_sent"].median()
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)

    return df


def calculer_resultats(df):
    """Calcule les 5 résultats demandés et les retourne dans un dictionnaire."""
    taux_deny = (df["action"] == "DENY").mean() * 100

    # int() et str() convertissent les types pandas en types acceptés par JSON
    return {
        "nb_lignes_apres_nettoyage": len(df),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float(taux_deny), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def ecrire_resultats(resultats, chemin):
    """Enregistre les résultats au format JSON."""
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(resultats, fichier, indent=2, ensure_ascii=False)


def tracer_barres(serie, titre, axe_x, axe_y, fichier, element_alerte=None):
    """Trace un graphique en barres horizontales, la plus grande valeur en haut."""
    serie = serie.sort_values()
    couleurs = [
        COULEUR_ALERTE if etiquette == element_alerte else COULEUR_NORMALE
        for etiquette in serie.index
    ]

    figure, axe = plt.subplots(figsize=(9, 5))
    barres = axe.barh(serie.index.astype(str), serie.values, color=couleurs)
    etiquettes = [f"{valeur:,.0f}".replace(",", " ") for valeur in serie.values]
    axe.bar_label(barres, labels=etiquettes, padding=4)
    axe.margins(x=0.12)
    axe.set_title(titre, loc="left", fontweight="bold")
    axe.set_xlabel(axe_x)
    axe.set_ylabel(axe_y)
    axe.spines[["top", "right"]].set_visible(False)

    figure.tight_layout()
    figure.savefig(fichier, dpi=150)
    plt.close(figure)


def figure_top_ports(df, dossier):
    """Figure 1 : les 8 ports de destination les plus utilisés."""
    top_ports = df["dst_port"].value_counts().head(8)
    top_ports.index = [NOMS_PORTS.get(port, str(port)) for port in top_ports.index]
    tracer_barres(
        top_ports,
        "Les 8 ports de destination les plus utilisés",
        "Nombre de connexions",
        "Port de destination",
        dossier / "top_ports.png",
    )


def figure_connexions_par_heure(df, dossier):
    """Figure 2 : l'activité du réseau heure par heure sur la semaine."""
    heures = pd.to_datetime(df["timestamp"])
    connexions = heures.dt.floor("h").value_counts().sort_index()

    figure, axe = plt.subplots(figsize=(10, 5))
    axe.plot(connexions.index, connexions.values, color=COULEUR_NORMALE, linewidth=2)

    pic = connexions.idxmax()
    axe.scatter([pic], [connexions[pic]], color=COULEUR_ALERTE, s=70, zorder=3)
    axe.annotate(
        f"Pic : {connexions[pic]} connexions\nle {pic:%d/%m à %Hh}",
        xy=(pic, connexions[pic]),
        xytext=(15, -10),
        textcoords="offset points",
    )

    axe.set_title("Connexions par heure sur la semaine", loc="left", fontweight="bold")
    axe.set_xlabel("Date")
    axe.set_ylabel("Nombre de connexions")
    axe.spines[["top", "right"]].set_visible(False)

    figure.autofmt_xdate()
    figure.tight_layout()
    figure.savefig(dossier / "connexions_par_heure.png", dpi=150)
    plt.close(figure)


def figure_octets_par_appareil(df, dossier):
    """Figure 3 : le volume total envoyé par chaque type d'appareil."""
    mega_octets = df.groupby("device_type")["bytes_sent"].sum() / 1_000_000
    tracer_barres(
        mega_octets,
        "Volume de données envoyé par type d'appareil",
        "Total envoyé (Mo)",
        "Type d'appareil",
        dossier / "octets_par_appareil.png",
        element_alerte=mega_octets.idxmax(),
    )


def figure_ports_par_ip(df, dossier):
    """Figure 4 : les adresses IP qui ont contacté le plus de ports distincts."""
    ports_distincts = df.groupby("src_ip")["dst_port"].nunique().nlargest(10)
    tracer_barres(
        ports_distincts,
        "Adresses IP ayant contacté le plus de ports distincts",
        "Nombre de ports distincts",
        "Adresse IP source",
        dossier / "ports_distincts_par_ip.png",
        element_alerte=ports_distincts.idxmax(),
    )


def figure_allow_deny(df, dossier):
    """Figure 5 : la répartition des connexions autorisées et bloquées."""
    actions = df["action"].value_counts()
    actions.index = actions.index.map({"ALLOW": "ALLOW (autorisé)", "DENY": "DENY (bloqué)"})
    tracer_barres(
        actions,
        "Répartition des connexions autorisées et bloquées",
        "Nombre de connexions",
        "Décision du pare-feu",
        dossier / "repartition_allow_deny.png",
    )


def creer_figures(df, dossier):
    """Crée le dossier des figures et enregistre tous les graphiques."""
    dossier.mkdir(exist_ok=True)
    figure_top_ports(df, dossier)
    figure_connexions_par_heure(df, dossier)
    figure_octets_par_appareil(df, dossier)
    figure_ports_par_ip(df, dossier)
    figure_allow_deny(df, dossier)


def main():
    df_brut = charger_donnees(FICHIER_LOGS)
    df = nettoyer_donnees(df_brut)

    resultats = calculer_resultats(df)
    ecrire_resultats(resultats, FICHIER_RESULTATS)
    creer_figures(df, DOSSIER_FIGURES)

    print(f"Lignes avant nettoyage : {len(df_brut)}")
    print(f"Lignes après nettoyage : {len(df)}")
    print(f"Résultats écrits dans {FICHIER_RESULTATS.name} :")
    print(json.dumps(resultats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
