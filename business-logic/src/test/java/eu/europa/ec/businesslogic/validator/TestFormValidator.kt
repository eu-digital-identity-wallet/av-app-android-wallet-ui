/*
 * Copyright (c) 2025 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.businesslogic.validator

import eu.europa.ec.businesslogic.controller.log.LogController
import eu.europa.ec.testlogic.base.TestApplication
import eu.europa.ec.testlogic.extension.runTest
import eu.europa.ec.testlogic.rule.CoroutineTestRule
import junit.framework.TestCase.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = TestApplication::class, sdk = [36])
class TestFormValidator {

    private val plainErrorMessage = "error message"

    @get:org.junit.Rule
    val coroutineRule = CoroutineTestRule()

    private lateinit var formValidation: FormValidator

    @Mock
    private lateinit var logController: LogController

    private val validationError = FormValidationResult(
        false,
        plainErrorMessage
    )

    private val validationSuccess = FormValidationResult(true)

    @Before
    fun before() {
        MockitoAnnotations.openMocks(this)
        formValidation = FormValidatorImpl(logController)
    }

    @Test
    fun testValidateNotEmptyRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateNotEmpty(plainErrorMessage))
        validateForm(
            rules = rules,
            value = "",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "test",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateUrlRule() = coroutineRule.runTest {
        val rules = listOf(
            Rule.ValidateUrl(
                shouldValidateSchema = true,
                shouldValidateHost = true,
                shouldValidatePath = true,
                shouldValidateQuery = true,
                errorMessage = plainErrorMessage
            )
        )

        // Valid URL
        validateForm(
            rules = rules,
            value = "https://www.example.com/path/to/resource?query=parameter&another=example",
            expectedValidationResult = validationSuccess
        )

        // No schema
        validateForm(
            rules = rules,
            value = "www.example.com/path/to/resource?query=parameter&another=example",
            expectedValidationResult = validationError
        )

        // No host
        validateForm(
            rules = rules,
            value = "https:///path/to/resource?query=parameter&another=example",
            expectedValidationResult = validationError
        )

        // No path
        validateForm(
            rules = rules,
            value = "https://www.example.com?query=parameter&another=example",
            expectedValidationResult = validationError
        )

        // No query
        validateForm(
            rules = rules,
            value = "https://www.example.com/path/to/resource",
            expectedValidationResult = validationError
        )

        // Empty URL
        validateForm(
            rules = rules,
            value = "",
            expectedValidationResult = validationError
        )

        // Invalid URL #1
        validateForm(
            rules = rules,
            value = "invalid-url",
            expectedValidationResult = validationError
        )

        // Invalid URL #2
        validateForm(
            rules = rules,
            value = "123456789",
            expectedValidationResult = validationError
        )
    }

    @Test
    fun testValidateProjectUrlRule() = coroutineRule.runTest {
        val rules = listOf(
            Rule.ValidateUrl(
                shouldValidateSchema = true,
                shouldValidateHost = false,
                shouldValidatePath = false,
                shouldValidateQuery = true,
                errorMessage = plainErrorMessage
            )
        )

        // Test with invalid URLs
        validateForm(
            rules = rules,
            value = "",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "invalid_url",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "123456789",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "http://example.com",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "https://notarealproject.com/otherpath",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "https://notarealproject.com/bad_query_param?",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "ftp://projectsite.com",
            expectedValidationResult = validationError
        )

        // Test with valid URLs
        validateForm(
            rules = rules,
            value = "mocked_scheme://?mocked_query_param=some_value",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "mocked_scheme://mocked_host?mocked_query_param=some_value",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "mocked_scheme://mocked_host?mocked_query_param1=some_value1&mocked_query_param2=some_value2",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "mocked-scheme://mocked-host?mocked-query-param=some-value",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "mocked.scheme://mocked.host?mocked.query.param=some.value",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "eudi-openid4vp%3A%2F%2Fdev.verifier-backend.eudiw.dev%3Fclient_id%3Ddev.verifier-backend.eudiw.dev%26request_uri%3Dhttps%3A%2F%2Fdev.verifier-backend.eudiw.dev%2Fwallet%2Frequest.jwt%2F1234",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "openid-credential-offer://credential_offer?credential_offer=%7B%22credential_issuer%22:%20%22https://dev.issuer.eudiw.dev%22%2C%20%22credential_configuration_ids%22:%20%5B%22eu.europa.ec.eudi.pid_mdoc%22%5D%2C%20%22grants%22:%20%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%20%7B%22pre-authorized_code%22:%20%22some_code%22%2C%20%22tx_code%22:%20%7B%22length%22:%205%2C%20%22input_mode%22:%20%22numeric%22%2C%20%22description%22:%20%22Please%20provide%20the%20one-time%20code.%22%7D%7D%7D%7D",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fdev.issuer-backend.eudiw.dev%22%2C%22credential_configuration_ids%22%3A%5B%22eu.europa.ec.eudi.pid_mso_mdoc%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22authorization_server%22%3A%22https%3A%2F%2Fdev.auth.eudiw.dev%2Frealms%2Fpid-issuer-realm%22%7D%7D%7D",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "eudi-openid4vp://dev.verifier-backend.eudiw.dev?client_id=dev.verifier-backend.eudiw.dev&request_uri=https://dev.verifier-backend.eudiw.dev/wallet/request.jwt/1234",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "openid-credential-offer://credential_offer?credential_offer={\"credential_issuer\": \"https://dev.issuer.eudiw.dev\", \"credential_configuration_ids\": [\"eu.europa.ec.eudi.pid_mdoc\"], \"grants\": {\"urn:ietf:params:oauth:grant-type:pre-authorized_code\": {\"pre-authorized_code\": \"some_code\", \"tx_code\": {\"length\": 5, \"input_mode\": \"numeric\", \"description\": \"Please provide the one-time code.\"}}}}",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "openid-credential-offer://?credential_offer={\"credential_issuer\":\"https://dev.issuer-backend.eudiw.dev\",\"credential_configuration_ids\":[\"eu.europa.ec.eudi.pid_mso_mdoc\"],\"grants\":{\"authorization_code\":{\"authorization_server\":\"https://dev.auth.eudiw.dev/realms/pid-issuer-realm\"}}}",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateEmailRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateEmail(plainErrorMessage))
        validateForm(
            rules = rules,
            value = "test@test",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "test@test.com",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidatePhoneNumberRule() = coroutineRule.runTest {
        val greekPhoneRule = listOf(Rule.ValidatePhoneNumber(plainErrorMessage, "GR"))
        val usPhoneRule = listOf(Rule.ValidatePhoneNumber(plainErrorMessage, "US"))
        validateForm(
            rules = greekPhoneRule,
            value = "1111111111",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = greekPhoneRule,
            value = "15223433333",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = greekPhoneRule,
            value = "6941111111",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = usPhoneRule,
            value = "6941111111",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = usPhoneRule,
            value = "6102458772",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateStringLengthRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateStringLength(listOf(10, 12), plainErrorMessage))
        validateForm(
            rules = rules,
            value = "123456789",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "12345678901",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "1234567890",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "123456789012",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateStringMaxLengthRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateStringMaxLength(10, plainErrorMessage))
        validateForm(
            rules = rules,
            value = "aaaaaaaaaaa",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "            ",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "aaaaaaaaa",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "aaaaaaaaaa",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateStringMinLengthRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateStringMinLength(5, plainErrorMessage))
        validateForm(
            rules = rules,
            value = "",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "aaaa",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "aaaaa",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "aaaaaaaaa",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateContainsRegexRule() = coroutineRule.runTest {
        val atLeast2DigitsRule =
            listOf(Rule.ContainsRegex("(.*\\d){2,}".toRegex(), plainErrorMessage))
        val atLeast2SpecialCharsRule =
            listOf(Rule.ContainsRegex("(.*[^a-zA-Z0-9]){2,}".toRegex(), plainErrorMessage))
        val atLeast3UppercaseCharactersRule =
            listOf(Rule.ContainsRegex("(.*[A-Z]){3,}".toRegex(), plainErrorMessage))

        validateForm(
            rules = atLeast2DigitsRule,
            value = "Test12",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeast2DigitsRule,
            value = "Test123",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeast2DigitsRule,
            value = "Test1",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = atLeast2DigitsRule,
            value = "Test",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = atLeast2SpecialCharsRule,
            value = "Test!@",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeast2SpecialCharsRule,
            value = "Test!@#",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeast2SpecialCharsRule,
            value = "Test!",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = atLeast2SpecialCharsRule,
            value = "Test",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = atLeast3UppercaseCharactersRule,
            value = "TestAA",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeast3UppercaseCharactersRule,
            value = "TAestAA",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeast3UppercaseCharactersRule,
            value = "TestA",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = atLeast3UppercaseCharactersRule,
            value = "Test",
            expectedValidationResult = validationError
        )
    }

    @Test
    fun testValidateRegexRule() = coroutineRule.runTest {
        val atLeastOneCapitalLetterRule =
            listOf(Rule.ValidateRegex(".*[A-Z].*".toRegex(), plainErrorMessage))
        val atLeastOneDigitRule =
            listOf(Rule.ValidateRegex(".*(\\d).*".toRegex(), plainErrorMessage))
        val atLeastOneSpecialCharRule =
            listOf(Rule.ValidateRegex(".*[^a-zA-Z0-9].*".toRegex(), plainErrorMessage))
        validateForm(
            rules = atLeastOneCapitalLetterRule,
            value = "test",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = atLeastOneCapitalLetterRule,
            value = "Test",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeastOneDigitRule,
            value = "test",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = atLeastOneDigitRule,
            value = "test1",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = atLeastOneSpecialCharRule,
            value = "test",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = atLeastOneSpecialCharRule,
            value = "test1@",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateStringRangeRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateStringRange(0..10, plainErrorMessage))
        validateForm(
            rules = rules,
            value = "aaaaaaaaaaa",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "aaaaaaaaaa",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateStringMatchRule() = coroutineRule.runTest {
        val isNotCaseSensitiveRule = listOf(Rule.ValidateStringMatch("test", plainErrorMessage))
        val isCaseSensitiveRule = listOf(Rule.ValidateStringMatch("test", plainErrorMessage, true))
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "testt",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "t!@#$",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "TEST",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "TEST",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "test",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateStringNotMatchRule() = coroutineRule.runTest {
        val isNotCaseSensitiveRule = listOf(Rule.ValidateStringNotMatch("test", plainErrorMessage))
        val isCaseSensitiveRule =
            listOf(Rule.ValidateStringNotMatch("test", plainErrorMessage, true))
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "test",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "TEST",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = isNotCaseSensitiveRule,
            value = "testt",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "test",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "Testss",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "TEST",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = isCaseSensitiveRule,
            value = "",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateDuplicateCharacterNotInConsecutiveOrderRule() = coroutineRule.runTest {
        val maxTimesOfConsecutiveOrder2Rule = listOf(
            Rule.ValidateDuplicateCharacterNotInConsecutiveOrder(
                2,
                plainErrorMessage
            )
        )
        val maxTimesOfConsecutiveOrder4Rule = listOf(
            Rule.ValidateDuplicateCharacterNotInConsecutiveOrder(
                4,
                plainErrorMessage
            )
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "1313",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "4356754",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "0191",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "1225",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "2332",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "454545454545454555444455455",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder2Rule,
            value = "0024",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder4Rule,
            value = "0024",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder4Rule,
            value = "0004",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder4Rule,
            value = "0000",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = maxTimesOfConsecutiveOrder4Rule,
            value = "35523456337777",
            expectedValidationResult = validationError
        )
    }

    @Test
    fun testValidateNumericNotInConsecutiveSequenceOrderRule() = coroutineRule.runTest {
        val rules = listOf(Rule.ValidateNumericNotInConsecutiveSequenceOrder(4, plainErrorMessage))
        validateForm(
            rules = rules,
            value = "1234",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "4321",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "9876",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "3210",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "0123",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "1235",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "9875",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "0124",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "0923",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "8834834835939534",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "TEST",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun validateMultipleForms() = coroutineRule.runTest {
        val forms = listOf(
            Form(
                mapOf(
                    listOf(
                        Rule.ValidateNumericNotInConsecutiveSequenceOrder(
                            2,
                            "ValidateNumericNotInConsecutiveSequenceOrder"
                        ),
                        Rule.ValidateNotEmpty(
                            "ValidateNotEmpty"
                        ),
                        Rule.ValidateDuplicateCharacterNotInConsecutiveOrder(
                            2,
                            "ValidateDuplicateCharacterNotInConsecutiveOrder"
                        ),
                        Rule.ValidateEmail(
                            "ValidateEmail"
                        ),
                        Rule.ValidateRegex(
                            ".*(\\d).*".toRegex(),
                            "ValidateRegex"
                        )
                    ) to "4412"
                )
            ),
            Form(
                mapOf(
                    listOf(
                        Rule.ValidateEmail(
                            "ValidateEmail"
                        ),
                        Rule.ValidateNotEmpty(
                            "ValidateNotEmpty"
                        ),
                        Rule.ValidateDuplicateCharacterNotInConsecutiveOrder(
                            2,
                            "ValidateDuplicateCharacterNotInConsecutiveOrder"
                        ),
                        Rule.ValidatePhoneNumber(
                            "ValidatePhoneNumber",
                            "GR"
                        ),
                        Rule.ValidateRegex(
                            ".*(\\d).*".toRegex(),
                            "ValidateRegex"
                        )
                    ) to "test@test.gr"
                )
            ),
            Form(
                mapOf(
                    listOf(
                        Rule.ValidateEmail(
                            "ValidateEmail"
                        ),
                        Rule.ValidateStringNotMatch(
                            "6991111111",
                            "ValidateStringNotMatch"
                        ),
                        Rule.ValidateDuplicateCharacterNotInConsecutiveOrder(
                            2,
                            "ValidateDuplicateCharacterNotInConsecutiveOrder"
                        ),
                        Rule.ValidatePhoneNumber(
                            "ValidatePhoneNumber",
                            "GR"
                        ),
                        Rule.ValidateRegex(
                            ".*[^a-zA-Z0-9].*".toRegex(),
                            "ValidateRegex"
                        )
                    ) to "6991111111"
                )
            )
        )

        val expectedValidationResult = FormsValidationResult(
            isValid = false,
            messages = listOf(
                "ValidateDuplicateCharacterNotInConsecutiveOrder",
                "ValidateEmail",
                "ValidatePhoneNumber",
                "ValidateRegex",
                "ValidateEmail",
                "ValidateStringNotMatch",
                "ValidateDuplicateCharacterNotInConsecutiveOrder",
                "ValidateRegex"
            )
        )
        val actualValidationResult = formValidation.validateForms(forms)

        assertEquals(expectedValidationResult, actualValidationResult)
    }

    @Test
    fun testStringShouldEndWithNumber() = coroutineRule.runTest {
        val rules = listOf(Rule.StringShouldEndWithNumber(plainErrorMessage))
        validateForm(
            rules = rules,
            value = "1.",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "1,",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "1*",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "1.00",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "1,00",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateFileExtension() = coroutineRule.runTest {
        val validExtensionList = listOf(".doc", ".ppt")

        val rules = listOf(
            Rule.ValidateFileExtension(
                errorMessage = plainErrorMessage,
                supportedExtensions = validExtensionList
            )
        )

        validateForm(
            rules = rules,
            value = "fileame.pdf",
            expectedValidationResult = validationError
        )
        validateForm(
            rules = rules,
            value = "asdf",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = rules,
            value = "lalala.doc",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "lala.ppt",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateFileSizeMaxSize() = coroutineRule.runTest {

        val rules = listOf(
            Rule.ValidateFileSizeMaxSize(
                errorMessage = plainErrorMessage,
                size = 100L
            )
        )

        validateForm(
            rules = rules,
            value = "200",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = rules,
            value = "100",
            expectedValidationResult = validationSuccess
        )
        validateForm(
            rules = rules,
            value = "99",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateMinimumAmount() = coroutineRule.runTest {
        val rules = listOf(
            Rule.ValidateMinimumAmount(
                minimumAmount = 5,
                errorMessage = plainErrorMessage,
            )
        )

        validateForm(
            rules = rules,
            value = "test",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = rules,
            value = "4",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = rules,
            value = "5",
            expectedValidationResult = validationSuccess
        )

        validateForm(
            rules = rules,
            value = "6",
            expectedValidationResult = validationSuccess
        )
    }

    @Test
    fun testValidateMaximumAmount() = coroutineRule.runTest {
        val rules = listOf(
            Rule.ValidateMaximumAmount(
                maximumAmount = 5,
                errorMessage = plainErrorMessage,
            )
        )

        validateForm(
            rules = rules,
            value = "test",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = rules,
            value = "6",
            expectedValidationResult = validationError
        )

        validateForm(
            rules = rules,
            value = "5",
            expectedValidationResult = validationSuccess
        )

        validateForm(
            rules = rules,
            value = "4",
            expectedValidationResult = validationSuccess
        )
    }

    private suspend fun validateForm(
        rules: List<Rule>,
        value: String,
        expectedValidationResult: FormValidationResult
    ) {
        val actualValidationResult = formValidation.validateForm(
            Form(mapOf(rules to value))
        )
        assertEquals(expectedValidationResult, actualValidationResult)
    }
}
