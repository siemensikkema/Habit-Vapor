@testable import Habit
import HTTP
import Nimble
import Quick

final class UserEndpointsSpec: QuickSpec {

    override func spec() {

        fdescribe("me") {

            var response: String?

            beforeEach {
                let userController = UserController()
                response = try! userController.me(try! Request(body: [:])) as? String
            }

            it("returns a response") {
                expect(response).toNot(beNil())
            }
        }
    }
}
