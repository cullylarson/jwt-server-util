module.exports = {
    'extends': ['standard'],
    'parser': 'babel-eslint',
    'env': {
        'es6': true,
        'jest': true,
    },
    'parserOptions': {
        'ecmaVersion': '2019',
        'sourceType': 'module',
    },
    'rules': {
        'indent': ['error', 4, {'SwitchCase': 1}],
        'keyword-spacing': 'off',
        'object-curly-spacing': 'off',
        'brace-style': ['error', 'stroustrup', {'allowSingleLine': true}],
        'quotes': ['error', 'single', {'avoidEscape': true}],
        'comma-dangle': ['error', 'always-multiline'],
        'operator-linebreak': ['error', 'before'],
        'space-before-function-paren': ['error', {
            'anonymous': 'never',
            'named': 'never',
            'asyncArrow': 'always',
        }],
    },
}
