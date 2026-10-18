"""Interface CobaltGuard : tableau de bord local avec collectes en arrière-plan."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import platform
from queue import Empty, Queue
import subprocess
from threading import Thread
from tkinter import filedialog, messagebox

import customtkinter as ctk

from cobaltguard.models import CheckResult, Status
from cobaltguard.reporting.json_report import render_json_report
from cobaltguard.reporting.text_report import render_text_report
from cobaltguard.services import AuditService


# Une seule palette cohérente, optimisée pour un affichage sombre.
BACKGROUND = "#080C17"
SIDEBAR = "#101525"
SURFACE = "#121A2B"
SURFACE_RAISED = "#192338"
BORDER = "#29334A"
TEXT = "#F1F5FF"
MUTED = "#A0ABC3"
PURPLE = "#9568F7"
PURPLE_HOVER = "#784EDD"
CYAN = "#59D8F6"
STATUS_COLORS = {
    Status.PASS: "#56DCB4",
    Status.WARNING: "#F8C76B",
    Status.FAIL: "#FF808A",
    Status.UNKNOWN: "#A8B4C9",
    Status.ERROR: "#FF8CC9",
}
STATUS_BACKGROUNDS = {
    Status.PASS: "#163B38",
    Status.WARNING: "#42341F",
    Status.FAIL: "#42232F",
    Status.UNKNOWN: "#293247",
    Status.ERROR: "#422639",
}


def _collect_results(
    service: AuditService, events: Queue[tuple[CheckResult, ...]]
) -> None:
    """Un thread travaille sur Windows et passe des objets, jamais des widgets."""
    try:
        results = service.run()
    except Exception as exc:
        results = (
            CheckResult(
                check_id="audit",
                title="Exécution de l'analyse",
                status=Status.ERROR,
                summary="Une erreur inattendue a interrompu l'analyse.",
                details=(f"Type d'erreur : {type(exc).__name__}.",),
                recommendations=(
                    "Relancez l'analyse et signalez le type d'erreur si elle persiste.",
                ),
            ),
        )
    events.put(results)


class CobaltGuardApp(ctk.CTk):
    """Application Windows : interface séparée du moteur d'audit en lecture seule."""

    def __init__(self, service: AuditService | None = None) -> None:
        super().__init__()
        self._service = service if service is not None else AuditService()
        self._events: Queue[tuple[CheckResult, ...]] = Queue()
        self._last_results: tuple[CheckResult, ...] | None = None
        self._last_txt_path: Path | None = None
        self._running = False
        self._closing = False
        self._poll_after_id: str | None = None

        self.title("CobaltGuard | Security Console")
        self.geometry("1160x770")
        self.minsize(860, 620)
        self.configure(fg_color=BACKGROUND)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_dashboard()

    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self, width=246, corner_radius=0, fg_color=SIDEBAR
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(10, weight=1)

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, padx=23, pady=(31, 14), sticky="ew")
        mark = ctk.CTkLabel(
            brand, text="CG", width=48, height=48, corner_radius=12,
            fg_color=PURPLE, text_color=TEXT,
            font=ctk.CTkFont(family="Segoe UI", size=19, weight="bold"),
        )
        mark.pack(side="left", padx=(0, 12))
        brand_copy = ctk.CTkFrame(brand, fg_color="transparent")
        brand_copy.pack(side="left")
        ctk.CTkLabel(
            brand_copy, text="COBALTGUARD", text_color=TEXT,
            font=ctk.CTkFont(family="Segoe UI", size=16, weight="bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            brand_copy, text="SECURITY CONSOLE", text_color=CYAN,
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
        ).pack(anchor="w")

        ctk.CTkFrame(sidebar, height=1, fg_color=BORDER).grid(
            row=1, column=0, sticky="ew", padx=22, pady=17
        )
        ctk.CTkLabel(
            sidebar, text="OPÉRATIONS", anchor="w", text_color=MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        ).grid(row=2, column=0, sticky="ew", padx=24, pady=(8, 11))

        self._start_button = self._side_button(
            sidebar, "Lancer l'audit", self._start_analysis,
            row=3, primary=True
        )
        self._export_txt_button = self._side_button(
            sidebar, "Exporter le rapport TXT",
            lambda: self._export_results("txt"), row=4, state="disabled"
        )
        self._export_json_button = self._side_button(
            sidebar, "Exporter le rapport JSON",
            lambda: self._export_results("json"), row=5, state="disabled"
        )
        self._open_button = self._side_button(
            sidebar, "Ouvrir dans Bloc-notes",
            self._open_saved_report, row=6, state="disabled"
        )

        scope = ctk.CTkFrame(
            sidebar, fg_color=SURFACE, corner_radius=14,
            border_width=1, border_color=BORDER
        )
        scope.grid(row=8, column=0, sticky="ew", padx=18, pady=(26, 10))
        ctk.CTkLabel(
            scope, text="●  MODE LOCAL", anchor="w", text_color=CYAN,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold")
        ).pack(fill="x", padx=15, pady=(14, 5))
        ctk.CTkLabel(
            scope,
            text="Analyses en lecture seule.\nAucun transfert de données.",
            text_color=MUTED, justify="left", anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=12),
        ).pack(fill="x", padx=15, pady=(0, 15))

        ctk.CTkLabel(
            sidebar, text="BETA 0.2  ·  WINDOWS ONLY",
            text_color=MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=10),
        ).grid(row=11, column=0, sticky="w", padx=24, pady=(0, 24))

    def _side_button(
        self, parent: ctk.CTkFrame, text: str, command: object,
        *, row: int, primary: bool = False, state: str = "normal"
    ) -> ctk.CTkButton:
        button = ctk.CTkButton(
            parent,
            text=text, command=command, height=42, corner_radius=10,
            fg_color=PURPLE if primary else SURFACE_RAISED,
            hover_color=PURPLE_HOVER if primary else BORDER,
            text_color=TEXT,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            anchor="w", border_spacing=13, state=state,
        )
        button.grid(row=row, column=0, sticky="ew", padx=18, pady=5)
        return button

    def _build_dashboard(self) -> None:
        self._main = ctk.CTkScrollableFrame(
            self, fg_color=BACKGROUND, corner_radius=0,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=PURPLE,
        )
        self._main.grid(row=0, column=1, sticky="nsew")
        self._main.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self._main, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=28, pady=(27, 18))
        ctk.CTkLabel(
            top, text="SYSTEM / SECURITY OVERVIEW",
            text_color=CYAN, anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            top, text="Tableau de bord",
            text_color=TEXT, anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=32, weight="bold"),
        ).pack(anchor="w", pady=(5, 1))
        ctk.CTkLabel(
            top,
            text="Analysez les protections Windows et interprétez les résultats.",
            text_color=MUTED, anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=13),
        ).pack(anchor="w")

        hero = ctk.CTkFrame(
            self._main, corner_radius=17, fg_color=SURFACE,
            border_width=1, border_color=BORDER
        )
        hero.grid(row=1, column=0, sticky="ew", padx=28, pady=(0, 16))
        hero.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hero, text="ÉTAT DU SCANNER", anchor="w", text_color=CYAN,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(15, 2))
        self._status_label = ctk.CTkLabel(
            hero, text="Prêt pour une première analyse",
            anchor="w", text_color=TEXT,
            font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"),
        )
        self._status_label.grid(row=1, column=0, sticky="ew", padx=20)
        self._status_detail = ctk.CTkLabel(
            hero, text="Aucune collecte ne démarre sans votre action.",
            anchor="w", text_color=MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=12),
        )
        self._status_detail.grid(
            row=2, column=0, sticky="ew", padx=20, pady=(0, 10)
        )
        self._progress = ctk.CTkProgressBar(
            hero, height=7, mode="determinate",
            progress_color=PURPLE, fg_color=BORDER,
        )
        self._progress.grid(
            row=3, column=0, sticky="ew", padx=20, pady=(0, 19)
        )
        self._progress.set(0)

        metrics = ctk.CTkFrame(self._main, fg_color="transparent")
        metrics.grid(row=2, column=0, sticky="ew", padx=28, pady=(0, 19))
        for i in range(3):
            metrics.grid_columnconfigure(i, weight=1, uniform="metrics")
        self._metric_labels: dict[str, ctk.CTkLabel] = {}
        for col, (key, label, accent) in enumerate(
            (
                ("total", "CONTRÔLES ANALYSÉS", TEXT),
                ("pass", "CONTRÔLES CONFORMES", STATUS_COLORS[Status.PASS]),
                ("attention", "À EXAMINER", STATUS_COLORS[Status.WARNING]),
            )
        ):
            panel = ctk.CTkFrame(
                metrics, fg_color=SURFACE, corner_radius=15,
                border_width=1, border_color=BORDER
            )
            panel.grid(row=0, column=col, sticky="ew",
                       padx=(0 if col == 0 else 5, 0 if col == 2 else 5))
            ctk.CTkLabel(
                panel, text=label, anchor="w", text_color=MUTED,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            ).pack(anchor="w", padx=17, pady=(15, 4))
            value = ctk.CTkLabel(
                panel, text="—", anchor="w", text_color=accent,
                font=ctk.CTkFont(family="Segoe UI", size=29, weight="bold"),
            )
            value.pack(anchor="w", padx=17, pady=(0, 13))
            self._metric_labels[key] = value

        heading = ctk.CTkFrame(self._main, fg_color="transparent")
        heading.grid(row=3, column=0, sticky="ew", padx=28, pady=(0, 9))
        ctk.CTkLabel(
            heading, text="RÉSULTATS DES CONTRÔLES", anchor="w",
            text_color=TEXT,
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
        ).pack(side="left")
        ctk.CTkLabel(
            heading, text="Détails accessibles sur chaque carte",
            anchor="e", text_color=MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=11),
        ).pack(side="right")

        self._results_frame = ctk.CTkFrame(
            self._main, fg_color="transparent"
        )
        self._results_frame.grid(
            row=4, column=0, sticky="ew", padx=28, pady=(0, 15)
        )
        self._results_frame.grid_columnconfigure(0, weight=1)
        self._empty_message()

        ctk.CTkLabel(
            self._main,
            text="Les résultats sont indicatifs : CobaltGuard ne remplace pas un antivirus.",
            anchor="w", text_color=MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=11),
        ).grid(row=5, column=0, sticky="ew", padx=28, pady=(0, 30))

    def _empty_message(self) -> None:
        placeholder = ctk.CTkFrame(
            self._results_frame, fg_color=SURFACE, corner_radius=15,
            border_width=1, border_color=BORDER,
        )
        placeholder.grid(row=0, column=0, sticky="ew", pady=5)
        ctk.CTkLabel(
            placeholder,
            text="Aucun résultat pour le moment",
            text_color=TEXT, font=ctk.CTkFont(
                family="Segoe UI", size=16, weight="bold"
            ),
        ).pack(anchor="w", padx=18, pady=(20, 5))
        ctk.CTkLabel(
            placeholder,
            text="Cliquez sur « Lancer l'audit » pour examiner Defender et le pare-feu.",
            text_color=MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=12),
        ).pack(anchor="w", padx=18, pady=(0, 20))

    def _clear_results(self) -> None:
        for widget in self._results_frame.winfo_children():
            widget.destroy()

    def _start_analysis(self) -> None:
        if self._running or self._closing:
            return
        self._running = True
        self._last_results = None
        self._last_txt_path = None
        self._start_button.configure(state="disabled")
        self._export_txt_button.configure(state="disabled")
        self._export_json_button.configure(state="disabled")
        self._open_button.configure(state="disabled")
        self._status_label.configure(text="Analyse en cours")
        self._status_detail.configure(
            text="Collecte sécurisée des informations Windows…"
        )
        for value in self._metric_labels.values():
            value.configure(text="—")
        self._clear_results()
        self._progress.configure(mode="indeterminate")
        self._progress.start()

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
                (CheckResult(
                    check_id="audit", title="Exécution de l'analyse",
                    status=Status.ERROR, summary="Le thread d'analyse n'a pas démarré.",
                    recommendations=("Redémarrez CobaltGuard.",),
                ),)
            )
            return
        self._poll_after_id = self.after(100, self._poll_results)

    def _poll_results(self) -> None:
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
        self._progress.stop()
        self._progress.configure(mode="determinate")
        self._progress.set(1)
        self._start_button.configure(state="normal")
        self._export_txt_button.configure(state="normal")
        self._export_json_button.configure(state="normal")
        flagged = sum(item.status is not Status.PASS for item in results)
        passed = sum(item.status is Status.PASS for item in results)
        self._metric_labels["total"].configure(text=str(len(results)))
        self._metric_labels["pass"].configure(text=str(passed))
        self._metric_labels["attention"].configure(text=str(flagged))
        self._status_label.configure(text="Analyse terminée")
        now = datetime.now().astimezone().strftime("%d/%m/%Y · %H:%M")
        self._status_detail.configure(
            text=f"{now}  ·  {len(results)} contrôle(s), {flagged} à examiner."
        )
        self._clear_results()
        for index, result in enumerate(results):
            self._show_result(index, result)

    def _show_result(self, index: int, result: CheckResult) -> None:
        color = STATUS_COLORS[result.status]
        card = ctk.CTkFrame(
            self._results_frame, fg_color=SURFACE, corner_radius=16,
            border_width=1, border_color=BORDER
        )
        card.grid(row=index, column=0, sticky="ew", pady=7)
        card.grid_columnconfigure(0, weight=1)

        title = ctk.CTkFrame(card, fg_color="transparent")
        title.grid(row=0, column=0, sticky="ew", padx=18, pady=(15, 7))
        title.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            title, text=result.title, text_color=TEXT, anchor="w",
            font=ctk.CTkFont(family="Segoe UI", size=17, weight="bold"),
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            title, text=result.status.value, text_color=color,
            fg_color=STATUS_BACKGROUNDS[result.status], corner_radius=8,
            width=90, height=29,
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold")
        ).grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(
            card, text=result.summary, text_color=MUTED,
            anchor="w", justify="left", wraplength=660,
            font=ctk.CTkFont(family="Segoe UI", size=13),
        ).grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))

        details = ctk.CTkFrame(card, fg_color=SURFACE_RAISED, corner_radius=10)
        details.grid(row=3, column=0, sticky="ew", padx=18, pady=(0, 15))
        details.grid_remove()
        if result.details:
            ctk.CTkLabel(
                details, text="OBSERVATIONS", text_color=CYAN, anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            ).pack(fill="x", padx=14, pady=(13, 5))
            ctk.CTkLabel(
                details,
                text="\n".join(f"• {line}" for line in result.details),
                text_color=TEXT, justify="left", anchor="w",
                wraplength=640,
                font=ctk.CTkFont(family="Segoe UI", size=12),
            ).pack(fill="x", padx=14, pady=(0, 11))
        if result.recommendations:
            ctk.CTkLabel(
                details, text="RECOMMANDATIONS", text_color=CYAN, anchor="w",
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            ).pack(fill="x", padx=14, pady=(5, 4))
            ctk.CTkLabel(
                details,
                text="\n".join(f"• {line}" for line in result.recommendations),
                text_color=TEXT, justify="left", anchor="w",
                wraplength=640,
                font=ctk.CTkFont(family="Segoe UI", size=12),
            ).pack(fill="x", padx=14, pady=(0, 13))

        if result.details or result.recommendations:
            def toggle() -> None:
                if details.winfo_ismapped():
                    details.grid_remove()
                    toggle_button.configure(text="Afficher les détails  +")
                else:
                    details.grid()
                    toggle_button.configure(text="Masquer les détails  −")

            toggle_button = ctk.CTkButton(
                card, text="Afficher les détails  +",
                command=toggle, fg_color="transparent",
                hover_color=SURFACE_RAISED, text_color=PURPLE,
                anchor="w", width=165, height=30,
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            )
            toggle_button.grid(
                row=2, column=0, sticky="w", padx=12, pady=(0, 9)
            )

    def _export_results(self, report_format: str) -> None:
        """L'utilisateur choisit le fichier : rien n'est sauvegardé spontanément."""
        if self._running or self._closing or self._last_results is None:
            return
        if report_format not in {"txt", "json"}:
            raise ValueError("Format de rapport non supporté.")
        extension = ".txt" if report_format == "txt" else ".json"
        path = filedialog.asksaveasfilename(
            parent=self, title="Enregistrer le rapport CobaltGuard",
            defaultextension=extension,
            initialfile=f"CobaltGuard-rapport{extension}",
            filetypes=[(f"Rapport {report_format.upper()}", f"*{extension}")],
        )
        if not path:
            return
        content = (
            render_text_report(self._last_results)
            if report_format == "txt"
            else render_json_report(self._last_results)
        )
        try:
            Path(path).write_text(
                content, encoding="utf-8-sig" if report_format == "txt" else "utf-8"
            )
        except OSError as exc:
            messagebox.showerror(
                "Export impossible", f"Enregistrement impossible : {exc}",
                parent=self
            )
            return

        if report_format == "txt":
            self._last_txt_path = Path(path)
            self._open_button.configure(state="normal")
        messagebox.showinfo(
            "Rapport enregistré",
            "Fichier enregistré localement. Relisez-le avant de le partager, "
            "car il peut contenir des informations sur votre PC.",
            parent=self,
        )

    def _open_saved_report(self) -> None:
        """Ouvre seulement le rapport TXT explicitement enregistré, sans shell."""
        path = self._last_txt_path
        if self._running or self._closing or path is None:
            return
        if not path.is_file():
            messagebox.showerror(
                "Rapport introuvable",
                "Le dernier rapport TXT n'existe plus à cet emplacement.",
                parent=self
            )
            self._open_button.configure(state="disabled")
            return
        if platform.system() != "Windows":
            messagebox.showerror(
                "Windows requis",
                "L'ouverture dans le Bloc-notes nécessite Windows.",
                parent=self
            )
            return
        try:
            system_root = os.environ.get("SystemRoot")
            if not system_root:
                raise FileNotFoundError("Répertoire Windows introuvable.")
            executable = Path(system_root) / "System32" / "notepad.exe"
            if not executable.is_file():
                raise FileNotFoundError("Bloc-notes introuvable.")
            subprocess.Popen(
                [str(executable), str(path)], shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as exc:
            messagebox.showerror(
                "Impossible d'ouvrir le Bloc-notes", str(exc), parent=self
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
    """Lance l'interface avec les contrôles Windows existants, inchangés."""
    ctk.set_appearance_mode("dark")
    app = CobaltGuardApp()
    app.mainloop()
