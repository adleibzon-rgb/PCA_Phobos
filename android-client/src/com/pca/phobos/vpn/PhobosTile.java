package com.pca.phobos.vpn;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/** Quick settings tile: on/off. The connect logic lives in MainActivity, which handles ACTION_TOGGLE and closes itself. */
public class PhobosTile extends TileService {
    @Override
    public void onStartListening() { update(); }

    @Override
    public void onClick() {
        Intent i = new Intent(this, MainActivity.class).setAction(MainActivity.ACTION_TOGGLE)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE));
        } else {
            startActivityAndCollapse(i);
        }
    }

    private void update() {
        Tile t = getQsTile();
        if (t == null) return;
        t.setState(MainActivity.tunnelUp() ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.updateTile();
    }

    /** Called by MainActivity after connect/disconnect so an open shade shows the new state. */
    static void refresh(android.content.Context c) {
        requestListeningState(c, new android.content.ComponentName(c, PhobosTile.class));
    }
}
