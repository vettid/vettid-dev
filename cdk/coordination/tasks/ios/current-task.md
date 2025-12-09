# Phase 12: Connections & Profile UI

## Overview
Implement the connections and profile management features using the new Phase 7 backend APIs.

## Priority Task 1: Connection Invitations

### 1. Create Connection Models
```swift
// Models/Connection.swift
import Foundation

struct Connection: Codable, Identifiable {
    let connectionId: String
    let peerGuid: String
    let peerDisplayName: String
    let peerProfile: PeerProfile?
    let status: String
    let createdAt: String
    let lastMessageAt: String?
    let unreadCount: Int

    var id: String { connectionId }

    enum CodingKeys: String, CodingKey {
        case connectionId = "connection_id"
        case peerGuid = "peer_guid"
        case peerDisplayName = "peer_display_name"
        case peerProfile = "peer_profile"
        case status
        case createdAt = "created_at"
        case lastMessageAt = "last_message_at"
        case unreadCount = "unread_count"
    }
}

struct PeerProfile: Codable {
    let avatarUrl: String?
    let bio: String?

    enum CodingKeys: String, CodingKey {
        case avatarUrl = "avatar_url"
        case bio
    }
}

struct ConnectionInvitation: Codable {
    let invitationId: String
    let inviteCode: String
    let publicKey: String
    let displayName: String
    let profileSnippet: PeerProfile?
    let expiresAt: String
    let maxUses: Int
    let shareUrl: String
    let qrPayload: String

    enum CodingKeys: String, CodingKey {
        case invitationId = "invitation_id"
        case inviteCode = "invite_code"
        case publicKey = "public_key"
        case displayName = "display_name"
        case profileSnippet = "profile_snippet"
        case expiresAt = "expires_at"
        case maxUses = "max_uses"
        case shareUrl = "share_url"
        case qrPayload = "qr_payload"
    }
}

struct CreateInvitationRequest: Codable {
    let displayName: String?
    let message: String?
    let expiresInHours: Int?
    let maxUses: Int?
    let includeProfile: Bool?

    enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
        case message
        case expiresInHours = "expires_in_hours"
        case maxUses = "max_uses"
        case includeProfile = "include_profile"
    }
}

struct AcceptInvitationRequest: Codable {
    let inviteCode: String
    let displayName: String?
    let includeProfile: Bool?

    enum CodingKeys: String, CodingKey {
        case inviteCode = "invite_code"
        case displayName = "display_name"
        case includeProfile = "include_profile"
    }
}

struct AcceptInvitationResponse: Codable {
    let connectionId: String
    let peerGuid: String
    let peerDisplayName: String
    let peerProfile: PeerProfile?
    let status: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case connectionId = "connection_id"
        case peerGuid = "peer_guid"
        case peerDisplayName = "peer_display_name"
        case peerProfile = "peer_profile"
        case status
        case createdAt = "created_at"
    }
}

struct ConnectionsListResponse: Codable {
    let connections: [Connection]
    let nextCursor: String?
    let hasMore: Bool

    enum CodingKeys: String, CodingKey {
        case connections
        case nextCursor = "next_cursor"
        case hasMore = "has_more"
    }
}

struct RevokeResponse: Codable {
    let connectionId: String
    let status: String
    let revokedAt: String

    enum CodingKeys: String, CodingKey {
        case connectionId = "connection_id"
        case status
        case revokedAt = "revoked_at"
    }
}
```

### 2. Create Connections API Service
```swift
// Services/ConnectionsApiService.swift
import Foundation

class ConnectionsApiService {
    private let apiClient: APIClient

    init(apiClient: APIClient) {
        self.apiClient = apiClient
    }

    func createInvitation(
        displayName: String? = nil,
        message: String? = nil,
        expiresInHours: Int = 168,
        maxUses: Int = 1
    ) async throws -> ConnectionInvitation {
        let request = CreateInvitationRequest(
            displayName: displayName,
            message: message,
            expiresInHours: expiresInHours,
            maxUses: maxUses,
            includeProfile: true
        )
        return try await apiClient.post("/member/connections/invitations", body: request)
    }

    func acceptInvitation(
        inviteCode: String,
        displayName: String? = nil
    ) async throws -> AcceptInvitationResponse {
        let request = AcceptInvitationRequest(
            inviteCode: inviteCode,
            displayName: displayName,
            includeProfile: true
        )
        return try await apiClient.post("/member/connections/accept", body: request)
    }

    func listConnections(
        status: String = "active",
        limit: Int = 50,
        cursor: String? = nil
    ) async throws -> ConnectionsListResponse {
        var queryItems: [URLQueryItem] = [
            URLQueryItem(name: "status", value: status),
            URLQueryItem(name: "limit", value: String(limit))
        ]
        if let cursor = cursor {
            queryItems.append(URLQueryItem(name: "cursor", value: cursor))
        }
        return try await apiClient.get("/member/connections", queryItems: queryItems)
    }

    func getConnection(connectionId: String) async throws -> Connection {
        return try await apiClient.get("/member/connections/\(connectionId)")
    }

    func revokeConnection(connectionId: String) async throws -> RevokeResponse {
        return try await apiClient.post("/member/connections/\(connectionId)/revoke")
    }

    func getConnectionProfile(connectionId: String) async throws -> PeerProfile {
        return try await apiClient.get("/member/connections/\(connectionId)/profile")
    }
}
```

### 3. Create QR Code Generator
```swift
// Utils/QRCodeGenerator.swift
import CoreImage
import UIKit
import SwiftUI

struct QRCodeGenerator {
    static func generate(from string: String, size: CGFloat = 200) -> UIImage? {
        let data = string.data(using: .utf8)

        guard let filter = CIFilter(name: "CIQRCodeGenerator") else {
            return nil
        }

        filter.setValue(data, forKey: "inputMessage")
        filter.setValue("H", forKey: "inputCorrectionLevel")

        guard let outputImage = filter.outputImage else {
            return nil
        }

        let scaleX = size / outputImage.extent.size.width
        let scaleY = size / outputImage.extent.size.height
        let transformedImage = outputImage.transformed(by: CGAffineTransform(scaleX: scaleX, y: scaleY))

        let context = CIContext()
        guard let cgImage = context.createCGImage(transformedImage, from: transformedImage.extent) else {
            return nil
        }

        return UIImage(cgImage: cgImage)
    }
}

// SwiftUI View for QR Code
struct QRCodeView: View {
    let content: String
    let size: CGFloat

    init(content: String, size: CGFloat = 200) {
        self.content = content
        self.size = size
    }

    var body: some View {
        if let image = QRCodeGenerator.generate(from: content, size: size) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
                .frame(width: size, height: size)
        } else {
            Rectangle()
                .fill(Color.gray.opacity(0.3))
                .frame(width: size, height: size)
                .overlay(Text("QR Error"))
        }
    }
}
```

### 4. Create QR Code Scanner
```swift
// Views/QRScannerView.swift
import SwiftUI
import AVFoundation

struct QRScannerView: UIViewControllerRepresentable {
    let onCodeScanned: (String) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onCodeScanned: onCodeScanned)
    }

    class Coordinator: NSObject, QRScannerDelegate {
        let onCodeScanned: (String) -> Void

        init(onCodeScanned: @escaping (String) -> Void) {
            self.onCodeScanned = onCodeScanned
        }

        func didScanCode(_ code: String) {
            onCodeScanned(code)
        }
    }
}

protocol QRScannerDelegate: AnyObject {
    func didScanCode(_ code: String)
}

class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: QRScannerDelegate?

    private var captureSession: AVCaptureSession?
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()
        setupCamera()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        hasScanned = false
        if captureSession?.isRunning == false {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                self?.captureSession?.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if captureSession?.isRunning == true {
            captureSession?.stopRunning()
        }
    }

    private func setupCamera() {
        let session = AVCaptureSession()

        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video),
              let videoInput = try? AVCaptureDeviceInput(device: videoCaptureDevice),
              session.canAddInput(videoInput) else {
            return
        }

        session.addInput(videoInput)

        let metadataOutput = AVCaptureMetadataOutput()

        guard session.canAddOutput(metadataOutput) else {
            return
        }

        session.addOutput(metadataOutput)
        metadataOutput.setMetadataObjectsDelegate(self, queue: .main)
        metadataOutput.metadataObjectTypes = [.qr]

        let previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.frame = view.layer.bounds
        previewLayer.videoGravity = .resizeAspectFill
        view.layer.addSublayer(previewLayer)

        self.captureSession = session
        self.previewLayer = previewLayer

        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !hasScanned,
              let metadataObject = metadataObjects.first,
              let readableObject = metadataObject as? AVMetadataMachineReadableCodeObject,
              let stringValue = readableObject.stringValue else {
            return
        }

        hasScanned = true
        AudioServicesPlaySystemSound(SystemSoundID(kSystemSoundID_Vibrate))
        delegate?.didScanCode(stringValue)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }
}
```

### 5. Create Connections ViewModel
```swift
// ViewModels/ConnectionsViewModel.swift
import Foundation
import Combine

@MainActor
class ConnectionsViewModel: ObservableObject {
    @Published var connections: [Connection] = []
    @Published var invitation: ConnectionInvitation?
    @Published var isLoading = false
    @Published var error: String?

    private let api: ConnectionsApiService

    init(api: ConnectionsApiService) {
        self.api = api
    }

    func loadConnections() {
        Task {
            isLoading = true
            do {
                let response = try await api.listConnections()
                connections = response.connections
            } catch {
                self.error = error.localizedDescription
            }
            isLoading = false
        }
    }

    func createInvitation() {
        Task {
            isLoading = true
            do {
                invitation = try await api.createInvitation()
            } catch {
                self.error = error.localizedDescription
            }
            isLoading = false
        }
    }

    func acceptInvitation(inviteCode: String) {
        Task {
            isLoading = true
            do {
                _ = try await api.acceptInvitation(inviteCode: inviteCode)
                loadConnections() // Refresh list
            } catch {
                self.error = error.localizedDescription
            }
            isLoading = false
        }
    }

    func revokeConnection(connectionId: String) {
        Task {
            do {
                _ = try await api.revokeConnection(connectionId: connectionId)
                loadConnections() // Refresh list
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    func clearInvitation() {
        invitation = nil
    }

    func clearError() {
        error = nil
    }
}
```

### 6. Create Connections UI
```swift
// Views/ConnectionsView.swift
import SwiftUI

struct ConnectionsView: View {
    @StateObject private var viewModel: ConnectionsViewModel
    @State private var showingInviteSheet = false
    @State private var showingScanner = false

    init(api: ConnectionsApiService) {
        _viewModel = StateObject(wrappedValue: ConnectionsViewModel(api: api))
    }

    var body: some View {
        NavigationStack {
            List {
                ForEach(viewModel.connections) { connection in
                    ConnectionRow(connection: connection)
                        .swipeActions(edge: .trailing) {
                            Button(role: .destructive) {
                                viewModel.revokeConnection(connectionId: connection.connectionId)
                            } label: {
                                Label("Revoke", systemImage: "xmark.circle")
                            }
                        }
                }
            }
            .navigationTitle("Connections")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button {
                            showingScanner = true
                        } label: {
                            Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                        }

                        Button {
                            viewModel.createInvitation()
                            showingInviteSheet = true
                        } label: {
                            Label("Create Invite", systemImage: "person.badge.plus")
                        }
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .refreshable {
                viewModel.loadConnections()
            }
            .overlay {
                if viewModel.isLoading && viewModel.connections.isEmpty {
                    ProgressView()
                }
            }
            .onAppear {
                viewModel.loadConnections()
            }
            .sheet(isPresented: $showingInviteSheet) {
                if let invitation = viewModel.invitation {
                    InvitationSheet(invitation: invitation) {
                        showingInviteSheet = false
                        viewModel.clearInvitation()
                    }
                } else {
                    ProgressView()
                }
            }
            .sheet(isPresented: $showingScanner) {
                ScannerSheet { code in
                    showingScanner = false
                    // Parse QR payload to extract invite code
                    if let data = code.data(using: .utf8),
                       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let inviteCode = json["code"] as? String {
                        viewModel.acceptInvitation(inviteCode: inviteCode)
                    } else if code.count == 6 {
                        // Might be just the code
                        viewModel.acceptInvitation(inviteCode: code)
                    }
                }
            }
            .alert("Error", isPresented: .init(
                get: { viewModel.error != nil },
                set: { if !$0 { viewModel.clearError() } }
            )) {
                Button("OK") { viewModel.clearError() }
            } message: {
                Text(viewModel.error ?? "")
            }
        }
    }
}

struct ConnectionRow: View {
    let connection: Connection

    var body: some View {
        HStack(spacing: 12) {
            // Avatar
            Circle()
                .fill(Color.blue)
                .frame(width: 48, height: 48)
                .overlay(
                    Text(String(connection.peerDisplayName.prefix(1)).uppercased())
                        .font(.title2)
                        .foregroundColor(.white)
                )

            VStack(alignment: .leading, spacing: 4) {
                Text(connection.peerDisplayName)
                    .font(.headline)

                if let bio = connection.peerProfile?.bio {
                    Text(bio)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            if connection.unreadCount > 0 {
                Text("\(connection.unreadCount)")
                    .font(.caption)
                    .foregroundColor(.white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(Color.red)
                    .clipShape(Capsule())
            }
        }
        .padding(.vertical, 4)
    }
}

struct InvitationSheet: View {
    let invitation: ConnectionInvitation
    let onDismiss: () -> Void

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Text("Share this QR code to connect")
                    .font(.headline)

                QRCodeView(content: invitation.qrPayload, size: 200)
                    .padding()
                    .background(Color.white)
                    .cornerRadius(12)

                VStack(spacing: 8) {
                    Text("Code: \(invitation.inviteCode)")
                        .font(.title2)
                        .fontWeight(.bold)

                    Text("Expires: \(invitation.expiresAt)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                ShareLink(
                    item: invitation.shareUrl,
                    subject: Text("VettID Connection Invite"),
                    message: Text("Connect with me on VettID! Use code: \(invitation.inviteCode)")
                ) {
                    Label("Share Invite", systemImage: "square.and.arrow.up")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(10)
                }
                .padding(.horizontal)

                Spacer()
            }
            .padding()
            .navigationTitle("Connection Invite")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done", action: onDismiss)
                }
            }
        }
    }
}

struct ScannerSheet: View {
    let onCodeScanned: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            QRScannerView(onCodeScanned: onCodeScanned)
                .navigationTitle("Scan QR Code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button("Cancel") {
                            dismiss()
                        }
                    }
                }
        }
    }
}
```

---

## Priority Task 2: Profile Management

### 1. Create Profile Models
```swift
// Models/Profile.swift
import Foundation

struct Profile: Codable {
    let guid: String
    let displayName: String?
    let avatarUrl: String?
    let bio: String?
    let location: String?
    let lastUpdated: String?
    let version: Int

    enum CodingKeys: String, CodingKey {
        case guid
        case displayName = "display_name"
        case avatarUrl = "avatar_url"
        case bio
        case location
        case lastUpdated = "last_updated"
        case version
    }
}

struct UpdateProfileRequest: Codable {
    let displayName: String?
    let avatarUrl: String?
    let bio: String?
    let location: String?

    enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
        case avatarUrl = "avatar_url"
        case bio
        case location
    }
}

struct PublishResponse: Codable {
    let published: Bool
    let connectionsNotified: Int

    enum CodingKeys: String, CodingKey {
        case published
        case connectionsNotified = "connections_notified"
    }
}
```

### 2. Create Profile API Service
```swift
// Services/ProfileApiService.swift
import Foundation

class ProfileApiService {
    private let apiClient: APIClient

    init(apiClient: APIClient) {
        self.apiClient = apiClient
    }

    func getProfile() async throws -> Profile {
        return try await apiClient.get("/member/profile")
    }

    func updateProfile(
        displayName: String? = nil,
        avatarUrl: String? = nil,
        bio: String? = nil,
        location: String? = nil
    ) async throws -> Profile {
        let request = UpdateProfileRequest(
            displayName: displayName,
            avatarUrl: avatarUrl,
            bio: bio,
            location: location
        )
        return try await apiClient.put("/member/profile", body: request)
    }

    func publishProfile() async throws -> PublishResponse {
        return try await apiClient.post("/member/profile/publish")
    }
}
```

### 3. Create Profile ViewModel
```swift
// ViewModels/ProfileViewModel.swift
import Foundation

@MainActor
class ProfileViewModel: ObservableObject {
    @Published var profile: Profile?
    @Published var isLoading = false
    @Published var isSaving = false
    @Published var error: String?

    // Editable fields
    @Published var displayName = ""
    @Published var bio = ""
    @Published var location = ""

    private let api: ProfileApiService

    init(api: ProfileApiService) {
        self.api = api
    }

    func loadProfile() {
        Task {
            isLoading = true
            do {
                profile = try await api.getProfile()
                // Populate editable fields
                displayName = profile?.displayName ?? ""
                bio = profile?.bio ?? ""
                location = profile?.location ?? ""
            } catch {
                self.error = error.localizedDescription
            }
            isLoading = false
        }
    }

    func saveProfile() {
        Task {
            isSaving = true
            do {
                profile = try await api.updateProfile(
                    displayName: displayName.isEmpty ? nil : displayName,
                    bio: bio.isEmpty ? nil : bio,
                    location: location.isEmpty ? nil : location
                )
                // Publish to connections
                _ = try await api.publishProfile()
            } catch {
                self.error = error.localizedDescription
            }
            isSaving = false
        }
    }
}
```

### 4. Create Profile Edit View
```swift
// Views/ProfileView.swift
import SwiftUI

struct ProfileView: View {
    @StateObject private var viewModel: ProfileViewModel
    @State private var isEditing = false

    init(api: ProfileApiService) {
        _viewModel = StateObject(wrappedValue: ProfileViewModel(api: api))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    // Avatar placeholder
                    HStack {
                        Spacer()
                        Circle()
                            .fill(Color.blue)
                            .frame(width: 80, height: 80)
                            .overlay(
                                Text(String(viewModel.displayName.prefix(1)).uppercased())
                                    .font(.largeTitle)
                                    .foregroundColor(.white)
                            )
                        Spacer()
                    }
                    .listRowBackground(Color.clear)
                }

                Section("Profile") {
                    if isEditing {
                        TextField("Display Name", text: $viewModel.displayName)
                        TextField("Bio", text: $viewModel.bio, axis: .vertical)
                            .lineLimit(3...6)
                        TextField("Location", text: $viewModel.location)
                    } else {
                        LabeledContent("Display Name", value: viewModel.displayName)
                        LabeledContent("Bio", value: viewModel.bio.isEmpty ? "-" : viewModel.bio)
                        LabeledContent("Location", value: viewModel.location.isEmpty ? "-" : viewModel.location)
                    }
                }

                if let profile = viewModel.profile {
                    Section("Info") {
                        LabeledContent("Version", value: "\(profile.version)")
                        if let lastUpdated = profile.lastUpdated {
                            LabeledContent("Last Updated", value: lastUpdated)
                        }
                    }
                }
            }
            .navigationTitle("Profile")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if isEditing {
                        Button("Save") {
                            viewModel.saveProfile()
                            isEditing = false
                        }
                        .disabled(viewModel.isSaving)
                    } else {
                        Button("Edit") {
                            isEditing = true
                        }
                    }
                }

                if isEditing {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button("Cancel") {
                            // Reset to original values
                            viewModel.displayName = viewModel.profile?.displayName ?? ""
                            viewModel.bio = viewModel.profile?.bio ?? ""
                            viewModel.location = viewModel.profile?.location ?? ""
                            isEditing = false
                        }
                    }
                }
            }
            .overlay {
                if viewModel.isLoading {
                    ProgressView()
                }
            }
            .onAppear {
                viewModel.loadProfile()
            }
            .alert("Error", isPresented: .init(
                get: { viewModel.error != nil },
                set: { if !$0 { viewModel.error = nil } }
            )) {
                Button("OK") { viewModel.error = nil }
            } message: {
                Text(viewModel.error ?? "")
            }
        }
    }
}
```

---

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/member/connections/invitations` | Create connection invitation |
| POST | `/member/connections/accept` | Accept invitation |
| GET | `/member/connections` | List connections |
| GET | `/member/connections/{id}` | Get connection details |
| POST | `/member/connections/{id}/revoke` | Revoke connection |
| GET | `/member/connections/{id}/profile` | Get peer's profile |
| GET | `/member/profile` | Get own profile |
| PUT | `/member/profile` | Update profile |
| POST | `/member/profile/publish` | Publish to connections |

---

## Deliverables
- [ ] Connection models created
- [ ] ConnectionsApiService implemented
- [ ] QR code generation working (CoreImage)
- [ ] QR code scanning working (AVFoundation)
- [ ] ConnectionsViewModel implemented
- [ ] Connections list UI (SwiftUI)
- [ ] Create invitation sheet with QR
- [ ] Accept invitation flow
- [ ] Profile models created
- [ ] ProfileApiService implemented
- [ ] Profile edit view
- [ ] Unit tests for connections logic

## Notes
- X25519 key exchange happens server-side - app just sends/receives codes
- QR payload contains the full invitation data for offline scanning
- Invite codes are 6 characters, case-insensitive (e.g., "ABC123")
- Connection invitations expire (default 7 days, max 30 days)
- Always include profile when accepting for better UX
- Use `actor` for thread-safe API service if needed
- Consider using Combine for reactive updates
