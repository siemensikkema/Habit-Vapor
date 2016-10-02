@testable import Habit
import Fluent
import HTTP
import JSON
import Nimble
import Quick
import Turnstile

final class UserEndpointsSpec: QuickSpec {

    override func spec() {

        beforeEach {
            Database.default = Database(MemoryDriver())
        }

        describe("me") {

            var response: JSON?
            var error: Error?

            func performMeRequest(with user: User? = nil) {
                do {
                    let userController = UserController()

                    let request = try Request(body: "")

                    if var user = user {
                        try user.save()
                        if let id = user.id?.string {
                            let credentials = AuthenticatedUserCredentials(
                                id: id,
                                lastPasswordUpdate: Date())
                            let subject = Subject(turnstile: .testTurnstile)
                            request.storage["subject"] = subject
                            try subject.login(credentials : credentials, persist: false)
                        }
                    }

                    response = try (try userController.me(request) as? Habit.User)?
                        .makeResponse()
                        .json
                } catch let e {
                    error = e
                }
            }

            context("nonexisting user") {

                beforeEach {
                    performMeRequest()
                }

                it("fails") {
                    expect(error).toNot(beNil())
                }
            }

            context("existing user") {

                describe("response") {

                    beforeEach {
                        performMeRequest(with: .testUser())
                    }

                    it("contains name and email") {
                        expect(response) == JSON([
                            "email": .string(User.testEmail),
                            "name": .string(User.testName)])
                    }
                }
            }
        }
    }
}
