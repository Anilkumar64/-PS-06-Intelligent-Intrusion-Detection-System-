#include <QApplication>
#include <QSplashScreen>
#include <QPixmap>
#include <QPainter>
#include <QThread>
#include <QMessageBox>
#include <QFont>
#include <unistd.h>

#include "src/ui/MainWindow.h"

// ── Splash screen ─────────────────────────────────────────────────────────────
static QSplashScreen *showSplash()
{
    QPixmap px(480, 280);
    px.fill(QColor("#11131f"));

    QPainter p(&px);
    p.setPen(QColor("#5b9cf6"));
    p.setFont(QFont("Sans", 22, QFont::Bold));
    p.drawText(px.rect(), Qt::AlignCenter,
               "🛡  IDS\nIntelligent Intrusion\nDetection System");
    p.end();

    auto *splash = new QSplashScreen(px);
    splash->show();
    return splash;
}

// ─── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("IDS");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("PS-06");

    // ── Splash ────────────────────────────────────────────────────────────
    QSplashScreen *splash = showSplash();
    QApplication::processEvents();
    QThread::msleep(1000);

    // ── Root / capability check ───────────────────────────────────────────
    if (::getuid() != 0)
    {
        splash->hide();
        QMessageBox::warning(
            nullptr, "IDS — Permission Warning",
            "IDS is not running as root.\n\n"
            "Live packet capture requires root or CAP_NET_RAW.\n\n"
            "Run with:  sudo ./IDS_System\n"
            "Or grant:  sudo setcap cap_net_raw+eip ./IDS_System",
            QMessageBox::Ok);
        splash->show();
    }

    // ── Main window ───────────────────────────────────────────────────────
    MainWindow w;
    splash->finish(&w);
    delete splash;

    w.show();
    return app.exec();
}