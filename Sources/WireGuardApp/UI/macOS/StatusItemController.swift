// SPDX-License-Identifier: MIT
// Copyright © 2018-2020 WireGuard LLC. All Rights Reserved.

import Cocoa

class StatusItemController {
    #if VIRTUALSHIELD_VPN || VIRTUALSHIELD_WIREGUARD
    var currentTunnel: TunnelContainer? {
        didSet {
            updateStatusItemImage()
        }
    }
    #endif

    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let statusBarImageWhenActive = NSImage(named: "StatusBarIcon")!
    private let statusBarImageWhenInactive = NSImage(named: "StatusBarIconDimmed")!

    private let animationImages = [
        NSImage(named: "StatusBarIconDot1")!,
        NSImage(named: "StatusBarIconDot2")!,
        NSImage(named: "StatusBarIconDot3")!
    ]
    private var animationImageIndex: Int = 0
    private var animationTimer: Timer?

    init() {
        updateStatusItemImage()
    }

    func updateStatusItemImage() {
        #if VIRTUALSHIELD_VPN || VIRTUALSHIELD_WIREGUARD
        guard let currentTunnel = currentTunnel else {
            stopActivatingAnimation()
            statusItem.button?.image = statusBarImageWhenInactive
            return
        }
        switch currentTunnel.status {
        case .inactive:
            stopActivatingAnimation()
            statusItem.button?.image = statusBarImageWhenInactive
        case .active:
            stopActivatingAnimation()
            statusItem.button?.image = statusBarImageWhenActive
        case .activating, .waiting, .reasserting, .restarting, .deactivating:
            startActivatingAnimation()
        }
        #endif
    }

    func startActivatingAnimation() {
        guard animationTimer == nil else { return }
        let timer = Timer(timeInterval: 0.3, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.statusItem.button?.image = self.animationImages[self.animationImageIndex]
            self.animationImageIndex = (self.animationImageIndex + 1) % self.animationImages.count
        }
        RunLoop.main.add(timer, forMode: .common)
        animationTimer = timer
    }

    func stopActivatingAnimation() {
        guard let timer = self.animationTimer else { return }
        timer.invalidate()
        animationTimer = nil
        animationImageIndex = 0
    }
}
