// Swift example file for narsil-xref testing

import Foundation

// Protocol definition
protocol Drawable {
    func draw()
    var color: String { get set }
}

// Class definition
class Circle: Drawable {
    var radius: Double
    var color: String

    init(radius: Double, color: String) {
        self.radius = radius
        self.color = color
    }

    func draw() {
        print("Drawing a \(color) circle with radius \(radius)")
    }

    func area() -> Double {
        return Double.pi * radius * radius
    }
}

// Struct definition
struct Point {
    var x: Double
    var y: Double

    func distance(to other: Point) -> Double {
        let dx = x - other.x
        let dy = y - other.y
        return sqrt(dx * dx + dy * dy)
    }
}

// Enum definition
enum Direction {
    case north
    case south
    case east
    case west

    func opposite() -> Direction {
        switch self {
        case .north: return .south
        case .south: return .north
        case .east: return .west
        case .west: return .east
        }
    }
}

// Standalone function
func greet(name: String) -> String {
    return "Hello, \(name)!"
}

// Generic function
func swap<T>(_ a: inout T, _ b: inout T) {
    let temp = a
    a = b
    b = temp
}
