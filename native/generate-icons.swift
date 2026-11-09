import AppKit
import Foundation

let nativeDirectory = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.deletingLastPathComponent()
let repositoryDirectory = nativeDirectory.deletingLastPathComponent()
let iconDirectory = repositoryDirectory.appendingPathComponent("icons", isDirectory: true)
let buildDirectory = nativeDirectory.appendingPathComponent("build", isDirectory: true)

try FileManager.default.createDirectory(at: iconDirectory, withIntermediateDirectories: true)
try FileManager.default.createDirectory(at: buildDirectory, withIntermediateDirectories: true)

func bitmap(size: Int) throws -> NSBitmapImageRep {
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        throw NSError(domain: "OpenPasswordsIcons", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not create an icon bitmap."])
    }
    return rep
}

func configuredSymbol(_ name: String, pointSize: CGFloat) throws -> NSImage {
    guard let source = NSImage(systemSymbolName: name, accessibilityDescription: nil) else {
        throw NSError(domain: "OpenPasswordsIcons", code: 2, userInfo: [NSLocalizedDescriptionKey: "SF Symbol \(name) is unavailable on this Mac."])
    }
    let sizeConfiguration = NSImage.SymbolConfiguration(pointSize: pointSize, weight: .semibold)
    let colorConfiguration = NSImage.SymbolConfiguration(paletteColors: [.white])
    guard let image = source.withSymbolConfiguration(sizeConfiguration.applying(colorConfiguration)) else {
        throw NSError(domain: "OpenPasswordsIcons", code: 3, userInfo: [NSLocalizedDescriptionKey: "Could not configure SF Symbol \(name)."])
    }
    return image
}

func centeredRect(for image: NSImage, inside bounds: NSRect, maximumFraction: CGFloat) -> NSRect {
    let size = image.size
    let longestSide = max(size.width, size.height)
    guard longestSide > 0 else { return .zero }
    let scale = min(bounds.width, bounds.height) * maximumFraction / longestSide
    let fitted = NSSize(width: size.width * scale, height: size.height * scale)
    return NSRect(
        x: bounds.midX - fitted.width / 2,
        y: bounds.midY - fitted.height / 2,
        width: fitted.width,
        height: fitted.height
    )
}

func renderKeyIcon(size: Int, cornerRadiusFraction: CGFloat) throws -> NSBitmapImageRep {
    let rep = try bitmap(size: size)
    let bounds = NSRect(x: 0, y: 0, width: size, height: size)
    let context = NSGraphicsContext(bitmapImageRep: rep)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context?.imageInterpolation = .high
    NSColor.clear.setFill()
    bounds.fill()

    let radius = CGFloat(size) * cornerRadiusFraction
    let background = NSBezierPath(roundedRect: bounds, xRadius: radius, yRadius: radius)
    let gradient = NSGradient(colors: [
        NSColor(srgbRed: 0.16, green: 0.53, blue: 0.98, alpha: 1),
        NSColor(srgbRed: 0.07, green: 0.31, blue: 0.82, alpha: 1),
    ])!
    gradient.draw(in: background, angle: -45)

    let key = try configuredSymbol("key.horizontal.fill", pointSize: CGFloat(size) * 0.64)
    key.draw(in: centeredRect(for: key, inside: bounds, maximumFraction: 0.72))
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

func renderRefreshIcon(size: Int) throws -> NSBitmapImageRep {
    let rep = try bitmap(size: size)
    let bounds = NSRect(x: 0, y: 0, width: size, height: size)
    let context = NSGraphicsContext(bitmapImageRep: rep)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    context?.imageInterpolation = .high
    NSColor.clear.setFill()
    bounds.fill()

    let refresh = try configuredSymbol("arrow.clockwise", pointSize: CGFloat(size) * 0.72)
    refresh.draw(in: centeredRect(for: refresh, inside: bounds, maximumFraction: 0.78))
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

func writePNG(_ rep: NSBitmapImageRep, to url: URL) throws {
    guard let data = rep.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "OpenPasswordsIcons", code: 4, userInfo: [NSLocalizedDescriptionKey: "Could not encode \(url.lastPathComponent)."])
    }
    try data.write(to: url, options: .atomic)
}

for size in [16, 48, 128] {
    try writePNG(try renderKeyIcon(size: size, cornerRadiusFraction: 0.22), to: iconDirectory.appendingPathComponent("icon\(size).png"))
}
try writePNG(try renderRefreshIcon(size: 32), to: iconDirectory.appendingPathComponent("refresh-sf.png"))

let iconset = buildDirectory.appendingPathComponent("OpenPasswords.iconset", isDirectory: true)
if FileManager.default.fileExists(atPath: iconset.path) {
    try FileManager.default.removeItem(at: iconset)
}
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

let iconsetEntries: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]
for (name, size) in iconsetEntries {
    try writePNG(try renderKeyIcon(size: size, cornerRadiusFraction: 0.12), to: iconset.appendingPathComponent(name))
}

let iconFile = nativeDirectory.appendingPathComponent("OpenPasswords.icns")
let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", "-o", iconFile.path, iconset.path]
try iconutil.run()
iconutil.waitUntilExit()
guard iconutil.terminationStatus == 0 else {
    throw NSError(domain: "OpenPasswordsIcons", code: 5, userInfo: [NSLocalizedDescriptionKey: "iconutil could not build OpenPasswords.icns."])
}

print("Generated Open Passwords SF Symbol icons.")
