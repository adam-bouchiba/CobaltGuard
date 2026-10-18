"""Fenêtre principale et communication avec le thread d'analyse."""

from __future__ import annotations

from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from tkinter import filedialog, messagebox

import customtkinter as ctk

from cobaltguard.models import CheckResult, Status
from cobaltguard.reporting.json_report import render_json_report
from cobaltguard.services import AuditService


# Une couleur pour chaque thème : le texte reste lisible en mode clair et sombre.
STATUS_COLORS: dict[Status, tuple[str, str]] = {
    Status.PASS: ("#166534", "#86EFAC"),
    Status.WARNING: ("#854D0E", "#FDE047"),
    Status.FAIL: ("#991B1B", "#FCA5A5"),
    Status.UNKNOWN: ("#475569", "#CBD5E1"),
    Status.ERROR: ("#9D174D", "#F9A8D4"),
}


def _collect_results(
    service: AuditService, events: Queue[tuple[CheckResult, ...]]
) -> None:
    """Le worker ne connaît aucun widget et ne fait jamais d'appel à Tk."""
    try:
        results = service.run()
    except Exception as exc:
        # Dernier filet de sécurité : une erreur inattendue ne fige pas la fenêtre.
        results = (
            CheckResult(
                check_id="audit",
                title="Exécution de l'analyse",
                status=Status.ERROR,
                summary="Une erreur inattendue a interrompu l'analyse.",
                details=(f"Type d'erreur : {type(exc).__name__}.",),
                recommendations=(
                    "Relancez l'analyse. Si l'erreur persiste, signalez ce type "
                    "d'erreur dans une issue du projet.",
                ),
            ),
        )
    events.put(results)


class CobaltGuardApp(ctk.CTk):
    """Affiche les résultats fournis par un service indépendant de l'interface."""

    def __init__(self, service: AuditService | None = None) -> None:
        super().__init__()
        self._service = service if service is not None else AuditService()
        self._events: Queue[tuple[CheckResult, ...]] = Queue()
        self._last_results: tuple[CheckResult, ...] | None = None
        self._running = False
        self._closing = False
        self._poll_after_id: str | None = None

        self.title("CobaltGuard")
        self.geometry("900x720")
        self.minsize(740, 520)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=24, pady=(24, 12), sticky="ew")
        ctk.CTkLabel(
            header, text="CobaltGuard", font=ctk.CTkFont(size=30, weight="bold")
        ).pack(anchor="w")
        ctk.CTkLabel(
            header,
            text="Audit local de Microsoft Defender et du pare-feu Windows.",
            anchor="w",
        ).pack(anchor="w", pady=(6, 0))
        ctk.CTkLabel(
            header,
            text="Lecture seule · Aucune modification des paramètres de sécurité",
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=1, column=0, padx=24, pady=8, sticky="w")
        self._start_button = ctk.CTkButton(
            actions, text="Lancer l'analyse", command=self._start_analysis, height=38
        )
        self._start_button.pack(side="left", padx=(0, 12))
        self._export_button = ctk.CTkButton(
            actions,
            text="Exporter le rapport JSON",
            command=self._export_results,
            state="disabled",
            height=38,
        )
        self._export_button.pack(side="left")
        self._progress = ctk.CTkProgressBar(self, mode="determinate")
        self._progress.grid(row=2, column=0, padx=24, pady=(6, 0), sticky="ew")
        self._progress.set(0)
        self._status_label = ctk.CTkLabel(
            self,
            text="Prêt. L'analyse démarre uniquement à votre demande.",
            anchor="w",
        )
        self._status_label.grid(row=3, column=0, padx=24, pady=8, sticky="ew")

        self._results_frame = ctk.CTkScrollableFrame(self)
        self._results_frame.grid(
            row=4, column=0, padx=24, pady=(0, 12), sticky="nsew"
        )
        self._results_frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self._results_frame,
            text="Les observations et recommandations apparaîtront ici.",
            wraplength=620,
        ).grid(row=0, column=0, padx=16, pady=24, sticky="w")
        ctk.CTkLabel(
            self,
            text="PASS : conforme · WARNING : à examiner · FAIL : problème détecté\n"
            "UNKNOWN : information indisponible · ERROR : échec du contrôle",
            justify="left",
            anchor="w",
        ).grid(row=5, column=0, padx=24, pady=(0, 16), sticky="ew")

    def _start_analysis(self) -> None:
        if self._running or self._closing:
            return

        self._running = True
        self._last_results = None
        self._export_button.configure(state="disabled")
        self._start_button.configure(state="disabled")
        self._status_label.configure(text="Analyse en cours…")
        for widget in self._results_frame.winfo_children():
            widget.destroy()
        self._progress.configure(mode="indeterminate")
        self._progress.start()

        # Après fermeture, ce thread termine sa collecte sans toucher aux widgets.
        # Non daemon : Python laisse les délais PowerShell et leur nettoyage finir
        # avant de quitter (au plus les deux délais de collecte restants).
        worker = Thread(
            target=_collect_results,
            args=(self._service, self._events),
            name="cobaltguard-audit",
            daemon=False,
        )
        try:
            worker.start()
        except RuntimeError:
            self._finish_analysis(
                (
                    CheckResult(
                        check_id="audit",
                        title="Exécution de l'analyse",
                        status=Status.ERROR,
                        summary="Le thread d'analyse n'a pas pu démarrer.",
                        recommendations=("Fermez puis relancez CobaltGuard.",),
                    ),
                )
            )
            return
        self._poll_after_id = self.after(100, self._poll_results)

    def _poll_results(self) -> None:
        """after() exécute ce callback dans le thread principal de Tk."""
        self._poll_after_id = None
        if self._closing:
            return
        try:
            results = self._events.get_nowait()
        except Empty:
            self._poll_after_id = self.after(100, self._poll_results)
            return
        self._finish_analysis(results)

    def _finish_analysis(self, results: tuple[CheckResult, ...]) -> None:
        self._last_results = results
        self._running = False
        self._export_button.configure(state="normal")
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(0)
        self._start_button.configure(state="normal")
        self._status_label.configure(
            text=f"Analyse terminée · {len(results)} résultat(s). "
            "Consultez les statuts et les limites de chaque contrôle."
        )
        for row, result in enumerate(results):
            self._show_result(row, result)

    def _show_result(self, row: int, result: CheckResult) -> None:
        color = STATUS_COLORS[result.status]
        card = ctk.CTkFrame(self._results_frame, border_width=1, border_color=color)
        card.grid(row=row, column=0, padx=8, pady=8, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card,
            text=result.title,
            font=ctk.CTkFont(size=17, weight="bold"),
            anchor="w",
            wraplength=480,
            justify="left",
        ).grid(row=0, column=0, padx=16, pady=(12, 4), sticky="w")
        ctk.CTkLabel(
            card,
            text=result.status.value,
            font=ctk.CTkFont(weight="bold"),
            text_color=color,
        ).grid(row=0, column=1, padx=16, pady=(12, 4), sticky="e")
        ctk.CTkLabel(
            card, text=result.summary, wraplength=620, justify="left", anchor="w"
        ).grid(row=1, column=0, columnspan=2, padx=16, pady=(0, 8), sticky="ew")
        if result.details:
            ctk.CTkLabel(
                card,
                text="\n".join(f"• {detail}" for detail in result.details),
                wraplength=620,
                justify="left",
                anchor="w",
            ).grid(row=2, column=0, columnspan=2, padx=16, pady=(0, 8), sticky="ew")
        if result.recommendations:
            ctk.CTkLabel(
                card,
                text="Recommandations\n"
                + "\n".join(f"• {item}" for item in result.recommendations),
                wraplength=620,
                justify="left",
                anchor="w",
            ).grid(row=3, column=0, columnspan=2, padx=16, pady=(0, 12), sticky="ew")

    def _export_results(self) -> None:
        """Enregistrer un rapport uniquement sur demande explicite."""
        if self._running or self._closing or self._last_results is None:
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Enregistrer le rapport CobaltGuard",
            defaultextension=".json",
            initialfile="cobaltguard-report.json",
            filetypes=[("Rapport JSON", "*.json")],
        )
        if not path:
            return
        try:
            Path(path).write_text(
                render_json_report(self._last_results), encoding="utf-8"
            )
        except OSError as exc:
            messagebox.showerror(
                "Export impossible",
                f"Le rapport n'a pas pu être enregistré : {exc}",
                parent=self,
            )
            return
        messagebox.showinfo(
            "Rapport enregistré",
            "Le rapport est enregistré localement. Relisez-le avant de le partager : "
            "des informations sur votre ordinateur peuvent y figurer.",
            parent=self,
        )

    def _close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self._poll_after_id is not None:
            self.after_cancel(self._poll_after_id)
            self._poll_after_id = None
        self._progress.stop()
        self.destroy()


def main() -> None:
    """Point de lancement de l'application graphique."""
    ctk.set_appearance_mode("System")
    app = CobaltGuardApp()
    app.mainloop()
